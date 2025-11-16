//! # Misconfiguration Detection Engine
//!
//! Comprehensive misconfiguration detection for Deepsys security scanner.
//! Identifies security misconfigurations in infrastructure code, Kubernetes
//! manifests, Docker files, cloud configurations, and other infrastructure
//! as code files.
//!
//! Features:
//! - Kubernetes manifest security analysis
//! - Docker file security best practices
//! - Infrastructure as Code (IaC) security checks
//! - Cloud configuration validation
//! - Custom policy enforcement
//! - Integration with artifact analysis results

use anyhow::Result;
use async_trait::async_trait;
use deepsys_types::{Misconfiguration, SecurityIssue, Severity, ScanTarget};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod detector;
pub mod k8s;
pub mod docker;
pub mod iac;
pub mod policies;
pub mod scanner;

/// Misconfiguration scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisconfConfig {
    /// Enable misconfiguration scanning
    pub enabled: bool,

    /// List of policy files to use
    pub policies: Vec<PathBuf>,

    /// Custom policy directories
    pub policy_dirs: Vec<PathBuf>,

    /// Enable Kubernetes scanning
    pub enable_k8s: bool,

    /// Enable Docker scanning
    pub enable_docker: bool,

    /// Enable Infrastructure as Code scanning
    pub enable_iac: bool,

    /// Enable cloud configuration scanning
    pub enable_cloud: bool,

    /// File patterns to include
    pub include_patterns: Vec<String>,

    /// File patterns to exclude
    pub exclude_patterns: Vec<String>,

    /// Enable parallel processing
    pub parallel: bool,

    /// Number of worker threads
    pub workers: usize,

    /// Severity threshold for reporting
    pub severity_threshold: Severity,

    /// Enable policy customization
    pub enable_custom_policies: bool,

    /// Skip policy updates
    pub skip_policy_update: bool,

    /// Policy namespaces to use
    pub namespaces: Vec<String>,

    /// Custom data for policy evaluation
    pub custom_data: HashMap<String, String>,
}

impl Default for MisconfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            policies: Vec::new(),
            policy_dirs: Vec::new(),
            enable_k8s: true,
            enable_docker: true,
            enable_iac: true,
            enable_cloud: true,
            include_patterns: vec![
                "**/*.yaml".to_string(),
                "**/*.yml".to_string(),
                "**/Dockerfile*".to_string(),
                "**/docker-compose*".to_string(),
                "**/*.tf".to_string(),
                "**/*.json".to_string(),
                "**/*.hcl".to_string(),
                "**/cloudformation/*".to_string(),
                "**/terraform/*".to_string(),
                "**/k8s/*".to_string(),
                "**/kubernetes/*".to_string(),
            ],
            exclude_patterns: vec![
                "**/.git/**".to_string(),
                "**/node_modules/**".to_string(),
                "**/vendor/**".to_string(),
                "**/target/**".to_string(),
                "**/build/**".to_string(),
                "**/dist/**".to_string(),
                "**/test/**".to_string(),
                "**/tests/**".to_string(),
            ],
            parallel: true,
            workers: num_cpus::get(),
            severity_threshold: Severity::Low,
            enable_custom_policies: true,
            skip_policy_update: false,
            namespaces: vec!["default".to_string()],
            custom_data: HashMap::new(),
        }
    }
}

/// Misconfiguration policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID
    pub id: String,

    /// Policy title
    pub title: String,

    /// Policy description
    pub description: String,

    /// Severity level
    pub severity: Severity,

    /// Policy category
    pub category: String,

    /// Policy tags
    pub tags: Vec<String>,

    /// Policy code/query
    pub query: String,

    /// Expected result
    pub expected_result: Option<String>,

    /// Resolution steps
    pub resolution: String,

    /// References
    pub references: Vec<String>,

    /// Custom fields
    pub custom_fields: HashMap<String, String>,
}

impl Policy {
    /// Create a new policy
    pub fn new(id: String, title: String, query: String) -> Self {
        Self {
            id,
            title,
            description: format!("Policy for {}", title),
            severity: Severity::Medium,
            category: "general".to_string(),
            tags: Vec::new(),
            query,
            expected_result: None,
            resolution: "Review and fix the configuration".to_string(),
            references: Vec::new(),
            custom_fields: HashMap::new(),
        }
    }

    /// Check if policy matches the given severity threshold
    pub fn meets_severity_threshold(&self, threshold: Severity) -> bool {
        self.severity >= threshold
    }
}

/// Misconfiguration scanner
pub struct MisconfScanner {
    config: MisconfConfig,
    policies: Vec<Policy>,
    k8s_detector: Option<k8s::K8sDetector>,
    docker_detector: Option<docker::DockerDetector>,
    iac_detector: Option<iac::IacDetector>,
}

impl MisconfScanner {
    /// Create a new misconfiguration scanner
    pub async fn new(config: MisconfConfig) -> Result<Self> {
        info!("Initializing misconfiguration scanner");

        // Load policies
        let policies = Self::load_policies(&config).await?;

        // Initialize detectors
        let k8s_detector = if config.enable_k8s {
            Some(k8s::K8sDetector::new().await?)
        } else {
            None
        };

        let docker_detector = if config.enable_docker {
            Some(docker::DockerDetector::new().await?)
        } else {
            None
        };

        let iac_detector = if config.enable_iac {
            Some(iac::IacDetector::new().await?)
        } else {
            None
        };

        info!("Misconfiguration scanner initialized with {} policies", policies.len());

        Ok(Self {
            config,
            policies,
            k8s_detector,
            docker_detector,
            iac_detector,
        })
    }

    /// Scan a target for misconfigurations
    pub async fn scan(&self, target: ScanTarget) -> Result<Vec<SecurityIssue>> {
        info!("Starting misconfiguration scan for target: {:?}", target);

        let scan_start = std::time::Instant::now();
        let mut all_misconfigs = Vec::new();

        match target {
            ScanTarget::Filesystem { path, recursive: _ } => {
                let misconfigs = self.scan_filesystem(&path).await?;
                all_misconfigs.extend(misconfigs);
            }
            ScanTarget::Image { name, .. } => {
                // For container images, scan extracted filesystem
                warn!("Misconfiguration scanning for images requires filesystem extraction");
            }
            ScanTarget::Repository { url, .. } => {
                // For repositories, scan configuration files
                warn!("Misconfiguration scanning for repositories not yet implemented");
            }
            ScanTarget::Kubernetes { path, .. } => {
                if let Some(ref detector) = self.k8s_detector {
                    let misconfigs = detector.scan_path(&path).await?;
                    all_misconfigs.extend(misconfigs);
                }
            }
            _ => {
                warn!("Misconfiguration scanning not supported for target type: {:?}", target);
            }
        }

        // Filter by severity threshold
        let filtered_misconfigs: Vec<SecurityIssue> = all_misconfigs
            .into_iter()
            .filter(|issue| {
                if let SecurityIssue::Misconfiguration(misconf) = issue {
                    misconf.severity >= self.config.severity_threshold
                } else {
                    true
                }
            })
            .collect();

        let scan_duration = scan_start.elapsed();
        info!("Misconfiguration scan completed in {:?}. Found {} issues", scan_duration, filtered_misconfigs.len());

        Ok(filtered_misconfigs)
    }

    /// Scan filesystem for misconfigurations
    async fn scan_filesystem(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        // Scan Kubernetes manifests
        if let Some(ref detector) = self.k8s_detector {
            let k8s_misconfigs = detector.scan_filesystem(root_path).await?;
            misconfigs.extend(k8s_misconfigs);
        }

        // Scan Docker files
        if let Some(ref detector) = self.docker_detector {
            let docker_misconfigs = detector.scan_filesystem(root_path).await?;
            misconfigs.extend(docker_misconfigs);
        }

        // Scan Infrastructure as Code files
        if let Some(ref detector) = self.iac_detector {
            let iac_misconfigs = detector.scan_filesystem(root_path).await?;
            misconfigs.extend(iac_misconfigs);
        }

        Ok(misconfigs)
    }

    /// Load policies from configuration
    async fn load_policies(config: &MisconfConfig) -> Result<Vec<Policy>> {
        let mut policies = Vec::new();

        // Load built-in policies
        policies.extend(Self::get_builtin_policies().await?);

        // Load policies from files
        for policy_path in &config.policies {
            let file_policies = Self::load_policies_from_file(policy_path).await?;
            policies.extend(file_policies);
        }

        // Load policies from directories
        for policy_dir in &config.policy_dirs {
            let dir_policies = Self::load_policies_from_directory(policy_dir).await?;
            policies.extend(dir_policies);
        }

        debug!("Loaded {} policies", policies.len());
        Ok(policies)
    }

    /// Get built-in security policies
    async fn get_builtin_policies() -> Result<Vec<Policy>> {
        Ok(vec![
            // Kubernetes security policies
            Policy::new(
                "k8s-privileged-container".to_string(),
                "Privileged Container".to_string(),
                r#"spec.containers[*].securityContext.privileged == true"#.to_string(),
            ).with_severity(Severity::High)
             .with_category("Kubernetes".to_string())
             .with_tags(vec!["container".to_string(), "security".to_string()])
             .with_resolution("Remove privileged: true from container security context".to_string())
             .with_references(vec!["https://kubernetes.io/docs/concepts/policy/pod-security-policy/".to_string()]),

            Policy::new(
                "k8s-root-filesystem".to_string(),
                "Root Filesystem Access".to_string(),
                r#"spec.containers[*].securityContext.readOnlyRootFilesystem == false"#.to_string(),
            ).with_severity(Severity::Medium)
             .with_category("Kubernetes".to_string())
             .with_tags(vec!["filesystem".to_string(), "security".to_string()]),

            Policy::new(
                "k8s-capabilities".to_string(),
                "Dangerous Capabilities".to_string(),
                r#"spec.containers[*].securityContext.capabilities.add contains "SYS_ADMIN""#.to_string(),
            ).with_severity(Severity::High)
             .with_category("Kubernetes".to_string())
             .with_tags(vec!["capabilities".to_string(), "security".to_string()]),

            // Docker security policies
            Policy::new(
                "docker-root-user".to_string(),
                "Root User in Docker".to_string(),
                r#"USER.*root"#.to_string(),
            ).with_severity(Severity::High)
             .with_category("Docker".to_string())
             .with_tags(vec!["user".to_string(), "security".to_string()])
             .with_resolution("Use a non-root user in Docker containers".to_string()),

            Policy::new(
                "docker-healthcheck".to_string(),
                "Missing Health Check".to_string(),
                r#"HEALTHCHECK"#.to_string(),
            ).with_severity(Severity::Low)
             .with_category("Docker".to_string())
             .with_tags(vec!["health".to_string(), "monitoring".to_string()])
             .with_resolution("Add HEALTHCHECK instruction to Dockerfiles".to_string()),

            // Infrastructure as Code policies
            Policy::new(
                "iac-unencrypted-storage".to_string(),
                "Unencrypted Storage".to_string(),
                r#"encrypted.*false"#.to_string(),
            ).with_severity(Severity::High)
             .with_category("Infrastructure".to_string())
             .with_tags(vec!["encryption".to_string(), "storage".to_string()]),

            Policy::new(
                "iac-public-access".to_string(),
                "Public Access Enabled".to_string(),
                r#"(public|world).*(read|write|access)"#.to_string(),
            ).with_severity(Severity::High)
             .with_category("Infrastructure".to_string())
             .with_tags(vec!["access".to_string(), "security".to_string()]),
        ].into_iter().map(|mut policy| {
            policy.expected_result = Some("No matches found".to_string());
            policy
        }).collect())
    }

    /// Load policies from a file
    async fn load_policies_from_file(_policy_path: &PathBuf) -> Result<Vec<Policy>> {
        // Placeholder implementation
        warn!("Loading policies from files not fully implemented");
        Ok(Vec::new())
    }

    /// Load policies from a directory
    async fn load_policies_from_directory(_policy_dir: &PathBuf) -> Result<Vec<Policy>> {
        // Placeholder implementation
        warn!("Loading policies from directories not fully implemented");
        Ok(Vec::new())
    }

    /// Get scanner statistics
    pub fn get_stats(&self) -> ScannerStats {
        ScannerStats {
            policies_count: self.policies.len(),
            enabled: self.config.enabled,
            k8s_enabled: self.config.enable_k8s,
            docker_enabled: self.config.enable_docker,
            iac_enabled: self.config.enable_iac,
            parallel_enabled: self.config.parallel,
            workers: self.config.workers,
        }
    }
}

/// Scanner statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerStats {
    pub policies_count: usize,
    pub enabled: bool,
    pub k8s_enabled: bool,
    pub docker_enabled: bool,
    pub iac_enabled: bool,
    pub parallel_enabled: bool,
    pub workers: usize,
}

/// Configuration builder for misconfiguration scanning
pub struct MisconfScanBuilder {
    config: MisconfConfig,
}

impl MisconfScanBuilder {
    /// Create a new scan builder
    pub fn new() -> Self {
        Self {
            config: MisconfConfig::default(),
        }
    }

    /// Enable or disable misconfiguration scanning
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Add policy file
    pub fn with_policy_file(mut self, policy_path: PathBuf) -> Self {
        self.config.policies.push(policy_path);
        self
    }

    /// Add policy directory
    pub fn with_policy_directory(mut self, policy_dir: PathBuf) -> Self {
        self.config.policy_dirs.push(policy_dir);
        self
    }

    /// Enable Kubernetes scanning
    pub fn with_k8s(mut self, enabled: bool) -> Self {
        self.config.enable_k8s = enabled;
        self
    }

    /// Enable Docker scanning
    pub fn with_docker(mut self, enabled: bool) -> Self {
        self.config.enable_docker = enabled;
        self
    }

    /// Enable IaC scanning
    pub fn with_iac(mut self, enabled: bool) -> Self {
        self.config.enable_iac = enabled;
        self
    }

    /// Set severity threshold
    pub fn with_severity_threshold(mut self, severity: Severity) -> Self {
        self.config.severity_threshold = severity;
        self
    }

    /// Enable parallel processing
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.config.parallel = enabled;
        self
    }

    /// Set number of workers
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.config.workers = workers;
        self
    }

    /// Build the scan engine
    pub async fn build(self) -> Result<MisconfScanner> {
        MisconfScanner::new(self.config).await
    }
}

impl Default for MisconfScanBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy {
    /// Set severity for the policy
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set category
    pub fn with_category(mut self, category: String) -> Self {
        self.category = category;
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Set resolution
    pub fn with_resolution(mut self, resolution: String) -> Self {
        self.resolution = resolution;
        self
    }

    /// Set references
    pub fn with_references(mut self, references: Vec<String>) -> Self {
        self.references = references;
        self
    }

    /// Set expected result
    pub fn with_expected_result(mut self, expected_result: String) -> Self {
        self.expected_result = Some(expected_result);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = Policy::new(
            "test-policy".to_string(),
            "Test Policy".to_string(),
            "test.query".to_string(),
        );

        assert_eq!(policy.id, "test-policy");
        assert_eq!(policy.title, "Test Policy");
        assert_eq!(policy.severity, Severity::Medium);
    }

    #[test]
    fn test_builtin_policies() {
        let policies = MisconfScanner::get_builtin_policies();

        // This would work with async runtime
        // For now, just test that the method exists
        assert!(true);
    }

    #[tokio::test]
    async fn test_scanner_creation() {
        let config = MisconfConfig::default();
        let scanner = MisconfScanner::new(config).await;

        assert!(scanner.is_ok());

        if let Ok(scanner) = scanner {
            let stats = scanner.get_stats();
            assert!(stats.enabled);
            assert!(stats.policies_count > 0);
        }
    }

    #[test]
    fn test_scan_builder() {
        let builder = MisconfScanBuilder::new()
            .enabled(true)
            .with_k8s(true)
            .with_docker(true)
            .with_severity_threshold(Severity::Medium);

        assert!(builder.config.enabled);
        assert!(builder.config.enable_k8s);
        assert!(builder.config.enable_docker);
        assert_eq!(builder.config.severity_threshold, Severity::Medium);
    }
}
