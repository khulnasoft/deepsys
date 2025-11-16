//! OSV (Open Source Vulnerabilities) database client implementation

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use deepsys_types::{Vulnerability, Severity, DataSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use super::{VulnerabilityDatabase, DatabaseError, HttpConfig};

/// OSV API response structures
#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(rename = "vulns")]
    pub vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "summary")]
    pub summary: Option<String>,
    #[serde(rename = "details")]
    pub details: Option<String>,
    #[serde(rename = "aliases")]
    pub aliases: Option<Vec<String>>,
    #[serde(rename = "published")]
    pub published: Option<DateTime<Utc>>,
    #[serde(rename = "modified")]
    pub modified: Option<DateTime<Utc>>,
    #[serde(rename = "severity")]
    pub severity: Option<Vec<OsvSeverity>>,
    #[serde(rename = "references")]
    pub references: Option<Vec<OsvReference>>,
    #[serde(rename = "affected")]
    pub affected: Option<Vec<OsvAffected>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "score")]
    pub score: String,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "url")]
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(rename = "package")]
    pub package: OsvPackage,
    #[serde(rename = "ranges")]
    pub ranges: Option<Vec<OsvRange>>,
    #[serde(rename = "versions")]
    pub versions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "ecosystem")]
    pub ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "events")]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[serde(rename = "introduced")]
    pub introduced: Option<String>,
    #[serde(rename = "fixed")]
    pub fixed: Option<String>,
    #[serde(rename = "limit")]
    pub limit: Option<String>,
}

/// OSV client for querying the Open Source Vulnerabilities database
pub struct OsvClient {
    http_client: reqwest::Client,
    base_url: String,
}

impl OsvClient {
    /// Create a new OSV client
    pub fn new() -> Result<Self> {
        let http_config = HttpConfig::default();
        let client = reqwest::Client::builder()
            .timeout(http_config.timeout)
            .user_agent(http_config.user_agent)
            .build()?;

        Ok(Self {
            http_client: client,
            base_url: "https://api.osv.dev/v1".to_string(),
        })
    }

    /// Build URL for OSV API requests
    fn build_query_url(&self, package: &str, ecosystem: &str) -> String {
        format!("{}/query", self.base_url)
    }

    /// Parse severity from OSV data
    fn parse_severity(&self, severity_data: &[OsvSeverity]) -> Severity {
        for severity in severity_data {
            if severity.r#type == "CVSS_V3" {
                if let Ok(score) = severity.score.parse::<f32>() {
                    return match score {
                        score if score >= 9.0 => Severity::Critical,
                        score if score >= 7.0 => Severity::High,
                        score if score >= 4.0 => Severity::Medium,
                        score if score > 0.0 => Severity::Low,
                        _ => Severity::Unknown,
                    };
                }
            }
        }

        Severity::Unknown
    }

    /// Check if a version is affected by a vulnerability
    fn is_version_affected(&self, version: &str, affected: &OsvAffected) -> bool {
        // Check explicit version list
        if let Some(versions) = &affected.versions {
            return versions.contains(&version.to_string());
        }

        // Check version ranges
        if let Some(ranges) = &affected.ranges {
            for range in ranges {
                if self.is_version_in_range(version, range) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if version falls within a range
    fn is_version_in_range(&self, version: &str, range: &OsvRange) -> bool {
        // For simplicity, check if version matches any event in the range
        // In a real implementation, this would parse semantic versions properly
        for event in &range.events {
            if let Some(introduced) = &event.introduced {
                if version == introduced {
                    return true;
                }
            }
        }

        false
    }

    /// Convert OSV vulnerability to our Vulnerability type
    fn convert_osv_vulnerability(&self, osv_vuln: &OsvVulnerability) -> Result<Vulnerability> {
        // Get description
        let description = osv_vuln.summary.clone()
            .or_else(|| osv_vuln.details.clone())
            .unwrap_or_else(|| "No description available".to_string());

        // Parse severity
        let severity = osv_vuln.severity.as_ref()
            .map(|s| self.parse_severity(s))
            .unwrap_or(Severity::Unknown);

        // Collect references
        let references = osv_vuln.references.as_ref()
            .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
            .unwrap_or_default();

        Ok(Vulnerability {
            id: osv_vuln.id.clone(),
            package_name: "".to_string(), // Will be filled by caller
            package_version: "".to_string(), // Will be filled by caller
            severity,
            title: format!("OSV-{}", &osv_vuln.id),
            description,
            cvss_score: None, // OSV doesn't provide CVSS scores directly
            cvss_vector: None,
            references,
            fixed_version: None,
            published_date: osv_vuln.published,
            last_modified_date: osv_vuln.modified,
            data_source: None,
            file_path: None,
            line_number: None,
            custom_fields: HashMap::new(),
        })
    }

    /// Query OSV for a specific package
    async fn query_package(&self, package: &str, ecosystem: &str, version: &str) -> Result<Vec<Vulnerability>> {
        let query = OsvQuery {
            package: OsvPackageQuery {
                name: package.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: Some(version.to_string()),
        };

        let url = self.build_query_url(package, ecosystem);

        let response = self.http_client
            .post(&url)
            .json(&query)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("OSV API request failed: {}", response.status()));
        }

        let osv_response: OsvResponse = response.json().await?;

        let mut vulnerabilities = Vec::new();
        for osv_vuln in &osv_response.vulns {
            match self.convert_osv_vulnerability(osv_vuln) {
                Ok(mut vuln) => {
                    // Set package information
                    vuln.package_name = package.to_string();
                    vuln.package_version = version.to_string();

                    // Check if this version is actually affected
                    if let Some(affected) = &osv_vuln.affected {
                        if affected.iter().any(|a| self.is_version_affected(version, a)) {
                            vulnerabilities.push(vuln);
                        }
                    } else {
                        // If no affected ranges specified, include it
                        vulnerabilities.push(vuln);
                    }
                }
                Err(e) => eprintln!("Failed to convert OSV vulnerability: {}", e),
            }
        }

        Ok(vulnerabilities)
    }
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    #[serde(rename = "package")]
    pub package: OsvPackageQuery,
    #[serde(rename = "version")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsvPackageQuery {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "ecosystem")]
    pub ecosystem: String,
}

#[async_trait]
impl VulnerabilityDatabase for OsvClient {
    async fn get_vulnerabilities(&self, package: &str, version: &str) -> Result<Vec<Vulnerability>> {
        // Map package ecosystems to OSV ecosystems
        let ecosystem = self.map_ecosystem(package);

        self.query_package(package, &ecosystem, version).await
    }

    async fn search_vulnerabilities(&self, query: &str) -> Result<Vec<Vulnerability>> {
        // OSV doesn't have a general search API, so we'll return empty results
        // In a real implementation, we might search across multiple ecosystems
        Ok(Vec::new())
    }

    async fn get_vulnerability(&self, id: &str) -> Result<Option<Vulnerability>> {
        // OSV doesn't have a direct lookup by ID API, so we'll return None
        // In a real implementation, we might try to query and filter results
        Ok(None)
    }

    async fn get_metadata(&self) -> Result<DataSource> {
        Ok(DataSource {
            id: deepsys_types::SourceID::GitHubSecurityAdvisory,
            name: "Open Source Vulnerabilities (OSV)".to_string(),
            url: Some("https://osv.dev".to_string()),
            last_updated: Some(Utc::now()),
        })
    }

    async fn refresh(&self) -> Result<()> {
        // OSV is a service, no local refresh needed
        Ok(())
    }
}

impl OsvClient {
    /// Map package ecosystems to OSV ecosystems
    fn map_ecosystem(&self, package: &str) -> String {
        // This is a simplified mapping - in reality, we'd need more sophisticated detection
        if package.contains('/') {
            // Likely a Go module or similar
            "Go".to_string()
        } else if package.contains('.') && !package.contains('-') {
            // Likely a Python package
            "PyPI".to_string()
        } else if package.starts_with("npm:") {
            "npm".to_string()
        } else if package.starts_with("cargo:") {
            "crates.io".to_string()
        } else {
            // Default to generic ecosystem
            "OSS-Fuzz".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_client_creation() {
        let client = OsvClient::new().unwrap();
        assert_eq!(client.base_url, "https://api.osv.dev/v1");
    }

    #[test]
    fn test_ecosystem_mapping() {
        let client = OsvClient::new().unwrap();

        assert_eq!(client.map_ecosystem("github.com/user/repo"), "Go");
        assert_eq!(client.map_ecosystem("requests"), "PyPI");
        assert_eq!(client.map_ecosystem("npm:lodash"), "npm");
        assert_eq!(client.map_ecosystem("cargo:serde"), "crates.io");
    }

    #[test]
    fn test_severity_parsing() {
        let client = OsvClient::new().unwrap();

        let severity_data = vec![
            OsvSeverity {
                r#type: "CVSS_V3".to_string(),
                score: "9.8".to_string(),
            }
        ];

        let severity = client.parse_severity(&severity_data);
        assert_eq!(severity, Severity::Critical);
    }
}
