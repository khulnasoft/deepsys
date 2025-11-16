//! # Database Integration
//!
//! Vulnerability database connectivity and data management for Deepsys.
//! This crate provides interfaces to external vulnerability databases like
//! NVD, OSV, and other security advisories.

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use deepsys_types::{Vulnerability, Severity, SourceID, DataSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

pub mod nvd;
pub mod osv;
pub mod cache;

/// Database client trait for vulnerability data sources
#[async_trait]
pub trait VulnerabilityDatabase: Send + Sync {
    /// Get vulnerabilities for a specific package
    async fn get_vulnerabilities(&self, package: &str, version: &str) -> Result<Vec<Vulnerability>>;

    /// Search vulnerabilities by keyword
    async fn search_vulnerabilities(&self, query: &str) -> Result<Vec<Vulnerability>>;

    /// Get vulnerability by ID (e.g., CVE-2023-1234)
    async fn get_vulnerability(&self, id: &str) -> Result<Option<Vulnerability>>;

    /// Get database metadata
    async fn get_metadata(&self) -> Result<DataSource>;

    /// Refresh/update the database
    async fn refresh(&self) -> Result<()>;
}

/// Database manager for coordinating multiple vulnerability sources
pub struct DatabaseManager {
    databases: HashMap<SourceID, Box<dyn VulnerabilityDatabase>>,
    cache: Option<Box<dyn cache::VulnerabilityCache>>,
}

impl DatabaseManager {
    /// Create a new database manager
    pub fn new() -> Self {
        Self {
            databases: HashMap::new(),
            cache: None,
        }
    }

    /// Add a vulnerability database
    pub fn add_database(&mut self, source_id: SourceID, database: Box<dyn VulnerabilityDatabase>) {
        self.databases.insert(source_id, database);
    }

    /// Set cache backend
    pub fn set_cache(&mut self, cache: Box<dyn cache::VulnerabilityCache>) {
        self.cache = Some(cache);
    }

    /// Get vulnerabilities from all sources for a package
    pub async fn get_vulnerabilities(&self, package: &str, version: &str) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        for (_source_id, database) in &self.databases {
            match database.get_vulnerabilities(package, version).await {
                Ok(mut vulnerabilities) => {
                    // Add source information to each vulnerability
                    for vuln in &mut vulnerabilities {
                        vuln.data_source = Some(DataSource {
                            id: _source_id.clone(),
                            name: _source_id.to_string(),
                            url: None,
                            last_updated: Some(Utc::now()),
                        });
                    }
                    all_vulnerabilities.extend(vulnerabilities);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to query database {:?}: {}", _source_id, e);
                }
            }
        }

        // Remove duplicates and sort by severity
        all_vulnerabilities.sort_by(|a, b| b.severity.cmp(&a.severity));
        all_vulnerabilities.dedup_by(|a, b| a.id == b.id);

        Ok(all_vulnerabilities)
    }

    /// Search vulnerabilities across all databases
    pub async fn search_vulnerabilities(&self, query: &str) -> Result<Vec<Vulnerability>> {
        let mut all_vulnerabilities = Vec::new();

        for (_source_id, database) in &self.databases {
            match database.search_vulnerabilities(query).await {
                Ok(mut vulnerabilities) => {
                    // Add source information to each vulnerability
                    for vuln in &mut vulnerabilities {
                        vuln.data_source = Some(DataSource {
                            id: _source_id.clone(),
                            name: _source_id.to_string(),
                            url: None,
                            last_updated: Some(Utc::now()),
                        });
                    }
                    all_vulnerabilities.extend(vulnerabilities);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to search database {:?}: {}", _source_id, e);
                }
            }
        }

        // Remove duplicates and sort by severity
        all_vulnerabilities.sort_by(|a, b| b.severity.cmp(&a.severity));
        all_vulnerabilities.dedup_by(|a, b| a.id == b.id);

        Ok(all_vulnerabilities)
    }

    /// Get a specific vulnerability by ID
    pub async fn get_vulnerability(&self, id: &str) -> Result<Option<Vulnerability>> {
        for (_source_id, database) in &self.databases {
            if let Ok(Some(mut vulnerability)) = database.get_vulnerability(id).await {
                vulnerability.data_source = Some(DataSource {
                    id: _source_id.clone(),
                    name: _source_id.to_string(),
                    url: None,
                    last_updated: Some(Utc::now()),
                });
                return Ok(Some(vulnerability));
            }
        }
        Ok(None)
    }

    /// Refresh all databases
    pub async fn refresh_all(&self) -> Result<()> {
        for (_source_id, database) in &self.databases {
            match database.refresh().await {
                Ok(_) => println!("Successfully refreshed database: {:?}", _source_id),
                Err(e) => eprintln!("Failed to refresh database {:?}: {}", _source_id, e),
            }
        }
        Ok(())
    }

    /// Get all available databases
    pub fn get_databases(&self) -> Vec<SourceID> {
        self.databases.keys().cloned().collect()
    }
}

impl Default for DatabaseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a default database manager with common sources
pub async fn create_default_manager() -> Result<DatabaseManager> {
    let mut manager = DatabaseManager::new();

    // Add NVD database
    let nvd_client = nvd::NvdClient::new()?;
    manager.add_database(SourceID::NVD, Box::new(nvd_client));

    // Add OSV database
    let osv_client = osv::OsvClient::new()?;
    manager.add_database(SourceID::GitHubSecurityAdvisory, Box::new(osv_client));

    Ok(manager)
}

/// Vulnerability query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityQuery {
    pub package: String,
    pub version: Option<String>,
    pub ecosystem: Option<String>,
    pub severity: Option<Severity>,
    pub limit: Option<usize>,
}

impl VulnerabilityQuery {
    /// Create a new query for a specific package
    pub fn for_package(package: String, version: Option<String>) -> Self {
        Self {
            package,
            version,
            ecosystem: None,
            severity: None,
            limit: None,
        }
    }

    /// Set ecosystem filter
    pub fn with_ecosystem(mut self, ecosystem: String) -> Self {
        self.ecosystem = Some(ecosystem);
        self
    }

    /// Set severity filter
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set result limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Database error types
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database not found: {0}")]
    NotFound(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Rate limit exceeded")]
    RateLimit,

    #[error("Service unavailable")]
    ServiceUnavailable,
}

/// HTTP client configuration
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub timeout: std::time::Duration,
    pub user_agent: String,
    pub retry_attempts: u32,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
            user_agent: "deepsys/1.0".to_string(),
            retry_attempts: 3,
        }
    }
}

/// Vulnerability enrichment service
pub struct VulnerabilityEnricher {
    manager: DatabaseManager,
}

impl VulnerabilityEnricher {
    /// Create a new enricher
    pub fn new(manager: DatabaseManager) -> Self {
        Self { manager }
    }

    /// Enrich a vulnerability with additional data from databases
    pub async fn enrich_vulnerability(&self, mut vulnerability: Vulnerability) -> Result<Vulnerability> {
        // Try to find more information about this vulnerability
        if let Ok(Some(enriched)) = self.manager.get_vulnerability(&vulnerability.id).await {
            // Merge additional information
            if vulnerability.description.is_empty() && !enriched.description.is_empty() {
                vulnerability.description = enriched.description;
            }

            if vulnerability.references.is_empty() && !enriched.references.is_empty() {
                vulnerability.references = enriched.references;
            }

            if vulnerability.cvss_score.is_none() && enriched.cvss_score.is_some() {
                vulnerability.cvss_score = enriched.cvss_score;
            }
        }

        Ok(vulnerability)
    }

    /// Enrich multiple vulnerabilities
    pub async fn enrich_vulnerabilities(&self, vulnerabilities: Vec<Vulnerability>) -> Result<Vec<Vulnerability>> {
        let mut enriched = Vec::new();

        for vulnerability in vulnerabilities {
            match self.enrich_vulnerability(vulnerability).await {
                Ok(enriched_vuln) => enriched.push(enriched_vuln),
                Err(e) => {
                    eprintln!("Failed to enrich vulnerability {}: {}", vulnerability.id, e);
                    enriched.push(vulnerability);
                }
            }
        }

        Ok(enriched)
    }
}

/// Database health check
pub struct DatabaseHealthChecker {
    manager: DatabaseManager,
}

impl DatabaseHealthChecker {
    /// Create a new health checker
    pub fn new(manager: DatabaseManager) -> Self {
        Self { manager }
    }

    /// Check health of all databases
    pub async fn check_all(&self) -> Result<HashMap<SourceID, HealthStatus>> {
        let mut health = HashMap::new();

        for (source_id, database) in &self.manager.databases {
            match database.get_metadata().await {
                Ok(metadata) => {
                    health.insert(source_id.clone(), HealthStatus::Healthy {
                        last_updated: metadata.last_updated,
                        version: metadata.name,
                    });
                }
                Err(_) => {
                    health.insert(source_id.clone(), HealthStatus::Unhealthy);
                }
            }
        }

        Ok(health)
    }
}

/// Health status of a database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy {
        last_updated: Option<DateTime<Utc>>,
        version: String,
    },
    Unhealthy,
    Unknown,
}

/// Database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_databases: usize,
    pub healthy_databases: usize,
    pub total_vulnerabilities: usize,
    pub last_refresh: Option<DateTime<Utc>>,
}

impl DatabaseManager {
    /// Get database statistics
    pub async fn get_stats(&self) -> Result<DatabaseStats> {
        let total_databases = self.databases.len();
        let mut healthy_databases = 0;
        let mut total_vulnerabilities = 0;

        for (_source_id, database) in &self.databases {
            match database.get_metadata().await {
                Ok(_) => {
                    healthy_databases += 1;
                }
                Err(_) => {}
            }

            // Try to get a sample vulnerability count
            if let Ok(vulns) = database.search_vulnerabilities("test").await {
                total_vulnerabilities += vulns.len();
            }
        }

        Ok(DatabaseStats {
            total_databases,
            healthy_databases,
            total_vulnerabilities,
            last_refresh: Some(Utc::now()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_manager_creation() {
        let manager = DatabaseManager::new();
        assert_eq!(manager.get_databases().len(), 0);
    }

    #[test]
    fn test_vulnerability_query_creation() {
        let query = VulnerabilityQuery::for_package("openssl".to_string(), Some("1.1.1".to_string()))
            .with_ecosystem("cargo".to_string())
            .with_severity(Severity::High)
            .with_limit(10);

        assert_eq!(query.package, "openssl");
        assert_eq!(query.version, Some("1.1.1".to_string()));
        assert_eq!(query.ecosystem, Some("cargo".to_string()));
        assert_eq!(query.severity, Some(Severity::High));
        assert_eq!(query.limit, Some(10));
    }
}
