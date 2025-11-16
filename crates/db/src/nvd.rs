//! NVD (National Vulnerability Database) client implementation

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use deepsys_types::{Vulnerability, Severity, DataSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use super::{VulnerabilityDatabase, HttpConfig};

/// NVD API response structures
#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    pub total_results: u32,
    #[serde(rename = "vulnerabilities")]
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    #[serde(rename = "cve")]
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: String,
    #[serde(rename = "published")]
    pub published: DateTime<Utc>,
    #[serde(rename = "lastModified")]
    pub last_modified: DateTime<Utc>,
    #[serde(rename = "vulnStatus")]
    pub vuln_status: String,
    #[serde(rename = "descriptions")]
    pub descriptions: Vec<NvdDescription>,
    #[serde(rename = "metrics")]
    pub metrics: Option<NvdMetrics>,
    #[serde(rename = "references")]
    pub references: Vec<NvdReference>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    #[serde(rename = "lang")]
    pub lang: String,
    #[serde(rename = "value")]
    pub value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    pub cvss_v31: Option<Vec<NvdCvss>>,
    #[serde(rename = "cvssMetricV30")]
    pub cvss_v30: Option<Vec<NvdCvss>>,
    #[serde(rename = "cvssMetricV2")]
    pub cvss_v2: Option<Vec<NvdCvss>>,
}

#[derive(Debug, Deserialize)]
struct NvdCvss {
    #[serde(rename = "source")]
    pub source: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<f32>,
    #[serde(rename = "impactScore")]
    pub impact_score: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    #[serde(rename = "version")]
    pub version: String,
    #[serde(rename = "vectorString")]
    pub vector_string: Option<String>,
    #[serde(rename = "baseScore")]
    pub base_score: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(rename = "tags")]
    pub tags: Option<Vec<String>>,
}

/// NVD client for querying the National Vulnerability Database
pub struct NvdClient {
    http_client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl NvdClient {
    /// Create a new NVD client
    pub fn new() -> Result<Self> {
        let http_config = HttpConfig::default();
        let client = reqwest::Client::builder()
            .timeout(http_config.timeout)
            .user_agent(http_config.user_agent)
            .build()?;

        Ok(Self {
            http_client: client,
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
            api_key: None,
        })
    }

    /// Create a new NVD client with API key
    pub fn with_api_key(api_key: String) -> Result<Self> {
        let mut client = Self::new()?;
        client.api_key = Some(api_key);
        Ok(client)
    }

    /// Build URL for NVD API requests
    fn build_url(&self, params: &HashMap<&str, String>) -> String {
        let mut url = format!("{}/?", self.base_url);

        let mut param_strings = Vec::new();
        for (key, value) in params {
            param_strings.push(format!("{}={}", key, value));
        }

        url.push_str(&param_strings.join("&"));
        url
    }

    /// Parse CVSS score from NVD data
    fn parse_cvss_score(&self, metrics: &NvdMetrics) -> Option<f32> {
        // Prefer CVSS 3.1, then 3.0, then 2.0
        if let Some(cvss_v31) = &metrics.cvss_v31 {
            if let Some(cvss) = cvss_v31.first() {
                return cvss.cvss_data.base_score;
            }
        }

        if let Some(cvss_v30) = &metrics.cvss_v30 {
            if let Some(cvss) = cvss_v30.first() {
                return cvss.cvss_data.base_score;
            }
        }

        if let Some(cvss_v2) = &metrics.cvss_v2 {
            if let Some(cvss) = cvss_v2.first() {
                return cvss.cvss_data.base_score;
            }
        }

        None
    }

    /// Parse severity from CVSS score
    fn parse_severity(&self, score: Option<f32>) -> Severity {
        match score {
            Some(score) if score >= 9.0 => Severity::Critical,
            Some(score) if score >= 7.0 => Severity::High,
            Some(score) if score >= 4.0 => Severity::Medium,
            Some(score) if score > 0.0 => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    /// Convert NVD vulnerability to our Vulnerability type
    fn convert_nvd_vulnerability(&self, nvd_vuln: &NvdVulnerability) -> Result<Vulnerability> {
        let cve = &nvd_vuln.cve;

        // Get English description
        let description = cve.descriptions
            .iter()
            .find(|desc| desc.lang == "en")
            .map(|desc| desc.value.clone())
            .unwrap_or_else(|| "No description available".to_string());

        // Parse CVSS score
        let cvss_score = cve.metrics.as_ref()
            .map(|metrics| self.parse_cvss_score(metrics))
            .flatten();

        // Get CVSS vector
        let cvss_vector = cve.metrics.as_ref()
            .and_then(|metrics| {
                if let Some(cvss_v31) = &metrics.cvss_v31 {
                    cvss_v31.first().and_then(|cvss| cvss.cvss_data.vector_string.clone())
                } else if let Some(cvss_v30) = &metrics.cvss_v30 {
                    cvss_v30.first().and_then(|cvss| cvss.cvss_data.vector_string.clone())
                } else if let Some(cvss_v2) = &metrics.cvss_v2 {
                    cvss_v2.first().and_then(|cvss| cvss.cvss_data.vector_string.clone())
                } else {
                    None
                }
            });

        // Collect references
        let references = cve.references
            .iter()
            .filter_map(|r| r.url.clone())
            .collect();

        Ok(Vulnerability {
            id: cve.id.clone(),
            package_name: "".to_string(), // NVD doesn't provide package info
            package_version: "".to_string(),
            severity: self.parse_severity(cvss_score),
            title: format!("CVE-{}", &cve.id),
            description,
            cvss_score,
            cvss_vector,
            references,
            fixed_version: None,
            published_date: Some(cve.published),
            last_modified_date: Some(cve.last_modified),
            data_source: None,
            file_path: None,
            line_number: None,
            custom_fields: HashMap::new(),
        })
    }
}

#[async_trait]
impl VulnerabilityDatabase for NvdClient {
    async fn get_vulnerabilities(&self, package: &str, version: &str) -> Result<Vec<Vulnerability>> {
        // NVD doesn't support direct package queries, so we'll search by keyword
        self.search_vulnerabilities(&format!("{} {}", package, version)).await
    }

    async fn search_vulnerabilities(&self, query: &str) -> Result<Vec<Vulnerability>> {
        let mut params = HashMap::new();
        params.insert("keyword", query.to_string());

        let url = self.build_url(&params);

        let mut request = self.http_client.get(&url);

        // Add API key if available
        if let Some(api_key) = &self.api_key {
            request = request.header("apiKey", api_key);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("NVD API request failed: {}", response.status()));
        }

        let nvd_response: NvdResponse = response.json().await?;

        let mut vulnerabilities = Vec::new();
        for nvd_vuln in &nvd_response.vulnerabilities {
            match self.convert_nvd_vulnerability(nvd_vuln) {
                Ok(vuln) => vulnerabilities.push(vuln),
                Err(e) => eprintln!("Failed to convert NVD vulnerability: {}", e),
            }
        }

        Ok(vulnerabilities)
    }

    async fn get_vulnerability(&self, id: &str) -> Result<Option<Vulnerability>> {
        let mut params = HashMap::new();
        params.insert("cveId", id.to_string());

        let url = self.build_url(&params);

        let mut request = self.http_client.get(&url);

        if let Some(api_key) = &self.api_key {
            request = request.header("apiKey", api_key);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            return Err(anyhow!("NVD API request failed: {}", response.status()));
        }

        let nvd_response: NvdResponse = response.json().await?;

        if let Some(nvd_vuln) = nvd_response.vulnerabilities.first() {
            self.convert_nvd_vulnerability(nvd_vuln).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn get_metadata(&self) -> Result<DataSource> {
        // NVD doesn't have a metadata endpoint, so we'll create a basic metadata
        Ok(DataSource {
            id: deepsys_types::SourceID::NVD,
            name: "National Vulnerability Database".to_string(),
            url: Some("https://nvd.nist.gov".to_string()),
            last_updated: Some(Utc::now()),
        })
    }

    async fn refresh(&self) -> Result<()> {
        // NVD doesn't support manual refresh, data is updated automatically
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvd_client_creation() {
        let client = NvdClient::new().unwrap();
        assert_eq!(client.base_url, "https://services.nvd.nist.gov/rest/json/cves/2.0");
    }

    #[test]
    fn test_cvss_score_parsing() {
        let client = NvdClient::new().unwrap();

        let metrics = NvdMetrics {
            cvss_v31: Some(vec![NvdCvss {
                source: "nvd".to_string(),
                r#type: "Primary".to_string(),
                cvss_data: NvdCvssData {
                    version: "3.1".to_string(),
                    vector_string: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                    base_score: Some(9.8),
                },
                exploitability_score: Some(3.9),
                impact_score: Some(5.9),
            }]),
            cvss_v30: None,
            cvss_v2: None,
        };

        let score = client.parse_cvss_score(&metrics);
        assert_eq!(score, Some(9.8));

        let severity = client.parse_severity(score);
        assert_eq!(severity, Severity::Critical);
    }
}
