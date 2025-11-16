//! # Handlers
//!
//! Post-processing handlers for artifact analysis results. Handlers perform
//! additional operations on the analyzed data, such as vulnerability matching,
//! policy evaluation, and result filtering.

use anyhow::Result;
use async_trait::async_trait;
use deepsys_types::{SecurityIssue, Vulnerability, Misconfiguration, Secret, LicenseIssue};

use crate::{ArtifactInfo, types::HandlerType};

/// Trait for all handlers
#[async_trait]
pub trait Handler: Send + Sync {
    /// Get the type of this handler
    fn handler_type(&self) -> HandlerType;

    /// Handle the artifact information
    async fn handle(&self, info: &ArtifactInfo) -> Result<HandlerResult>;

    /// Check if this handler can handle the given artifact type
    fn can_handle(&self, artifact_type: &str) -> bool {
        true // Default implementation handles all types
    }
}

/// Result of handler processing
#[derive(Debug, Clone)]
pub struct HandlerResult {
    /// Issues found by this handler
    pub issues: Vec<SecurityIssue>,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Processing statistics
    pub stats: HandlerStats,
}

/// Handler processing statistics
#[derive(Debug, Clone, Default)]
pub struct HandlerStats {
    pub processing_time: std::time::Duration,
    pub items_processed: usize,
    pub items_matched: usize,
    pub errors: Vec<String>,
}

impl HandlerResult {
    /// Create a new handler result
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            metadata: std::collections::HashMap::new(),
            stats: HandlerStats::default(),
        }
    }

    /// Add an issue to the result
    pub fn add_issue(&mut self, issue: SecurityIssue) {
        self.issues.push(issue);
        self.stats.items_matched += 1;
    }

    /// Add metadata to the result
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Vulnerability database handler
pub mod vulnerability_db {
    use super::*;

    /// Handler for vulnerability database operations
    pub struct VulnerabilityDBHandler {
        db_path: Option<String>,
        enabled: bool,
    }

    impl VulnerabilityDBHandler {
        pub fn new() -> Self {
            Self {
                db_path: None,
                enabled: true,
            }
        }

        pub fn with_db_path<S: Into<String>>(mut self, path: S) -> Self {
            self.db_path = Some(path.into());
            self
        }

        pub fn enabled(mut self, enabled: bool) -> Self {
            self.enabled = enabled;
            self
        }
    }

    impl Default for VulnerabilityDBHandler {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl Handler for VulnerabilityDBHandler {
        fn handler_type(&self) -> HandlerType {
            HandlerType::VulnerabilityDB
        }

        async fn handle(&self, info: &ArtifactInfo) -> Result<HandlerResult> {
            let mut result = HandlerResult::new();
            let start_time = std::time::Instant::now();

            if !self.enabled {
                return Ok(result);
            }

            // Process packages for vulnerabilities
            for package in &info.packages {
                if let Some(vulnerabilities) = self.find_vulnerabilities(package).await? {
                    for vuln in vulnerabilities {
                        result.add_issue(SecurityIssue::Vulnerability(vuln));
                    }
                }
            }

            result.stats.processing_time = start_time.elapsed();
            result.stats.items_processed = info.packages.len();

            Ok(result)
        }

        fn can_handle(&self, artifact_type: &str) -> bool {
            matches!(artifact_type, "image" | "filesystem" | "repository")
        }
    }

    impl VulnerabilityDBHandler {
        async fn find_vulnerabilities(&self, package: &crate::Package) -> Result<Option<Vec<Vulnerability>>> {
            // Placeholder implementation
            // In a real implementation, this would query a vulnerability database
            Ok(None)
        }
    }
}

/// Policy handler for policy evaluation
pub mod policy {
    use super::*;

    /// Handler for policy evaluation and compliance checking
    pub struct PolicyHandler {
        policy_files: Vec<String>,
        enabled: bool,
    }

    impl PolicyHandler {
        pub fn new() -> Self {
            Self {
                policy_files: Vec::new(),
                enabled: true,
            }
        }

        pub fn with_policy_files(mut self, files: Vec<String>) -> Self {
            self.policy_files = files;
            self
        }

        pub fn enabled(mut self, enabled: bool) -> Self {
            self.enabled = enabled;
            self
        }
    }

    #[async_trait]
    impl Handler for PolicyHandler {
        fn handler_type(&self) -> HandlerType {
            HandlerType::Policy
        }

        async fn handle(&self, info: &ArtifactInfo) -> Result<HandlerResult> {
            let mut result = HandlerResult::new();
            let start_time = std::time::Instant::now();

            if !self.enabled {
                return Ok(result);
            }

            // Evaluate policies against the artifact
            for policy_file in &self.policy_files {
                if let Some(policy_issues) = self.evaluate_policy(policy_file, info).await? {
                    for issue in policy_issues {
                        result.add_issue(issue);
                    }
                }
            }

            result.stats.processing_time = start_time.elapsed();
            result.stats.items_processed = info.packages.len();

            Ok(result)
        }
    }

    impl PolicyHandler {
        async fn evaluate_policy(&self, policy_file: &str, info: &ArtifactInfo) -> Result<Option<Vec<SecurityIssue>>> {
            // Placeholder implementation
            Ok(None)
        }
    }
}

/// License handler for license compliance
pub mod license {
    use super::*;

    /// Handler for license compliance checking
    pub struct LicenseHandler {
        allowed_licenses: Vec<String>,
        forbidden_licenses: Vec<String>,
        enabled: bool,
    }

    impl LicenseHandler {
        pub fn new() -> Self {
            Self {
                allowed_licenses: Vec::new(),
                forbidden_licenses: Vec::new(),
                enabled: true,
            }
        }

        pub fn with_allowed_licenses(mut self, licenses: Vec<String>) -> Self {
            self.allowed_licenses = licenses;
            self
        }

        pub fn with_forbidden_licenses(mut self, licenses: Vec<String>) -> Self {
            self.forbidden_licenses = licenses;
            self
        }

        pub fn enabled(mut self, enabled: bool) -> Self {
            self.enabled = enabled;
            self
        }
    }

    #[async_trait]
    impl Handler for LicenseHandler {
        fn handler_type(&self) -> HandlerType {
            HandlerType::License
        }

        async fn handle(&self, info: &ArtifactInfo) -> Result<HandlerResult> {
            let mut result = HandlerResult::new();
            let start_time = std::time::Instant::now();

            if !self.enabled {
                return Ok(result);
            }

            // Check license compliance for all packages
            for package in &info.packages {
                if let Some(license_issue) = self.check_license_compliance(package).await? {
                    result.add_issue(SecurityIssue::License(license_issue));
                }
            }

            result.stats.processing_time = start_time.elapsed();
            result.stats.items_processed = info.packages.len();

            Ok(result)
        }
    }

    impl LicenseHandler {
        async fn check_license_compliance(&self, package: &crate::Package) -> Result<Option<LicenseIssue>> {
            // Placeholder implementation
            if let Some(ref license) = package.license {
                let compliance_status = if self.forbidden_licenses.contains(license) {
                    deepsys_types::ComplianceStatus::Forbidden
                } else if self.allowed_licenses.is_empty() || self.allowed_licenses.contains(license) {
                    deepsys_types::ComplianceStatus::Allowed
                } else {
                    deepsys_types::ComplianceStatus::Restricted
                };

                if matches!(compliance_status, deepsys_types::ComplianceStatus::Forbidden | deepsys_types::ComplianceStatus::Restricted) {
                    return Ok(Some(LicenseIssue {
                        license_name: license.clone(),
                        package_name: package.name.clone(),
                        package_version: package.version.clone(),
                        compliance_status,
                        allowed_licenses: self.allowed_licenses.clone(),
                        forbidden_licenses: self.forbidden_licenses.clone(),
                        custom_fields: std::collections::HashMap::new(),
                    }));
                }
            }

            Ok(None)
        }
    }
}

/// Secret handler for secret detection
pub mod secret {
    use super::*;

    /// Handler for secret detection and validation
    pub struct SecretHandler {
        rules: Vec<SecretRule>,
        enabled: bool,
    }

    /// Secret detection rule
    #[derive(Debug, Clone)]
    pub struct SecretRule {
        pub id: String,
        pub name: String,
        pub pattern: regex::Regex,
        pub severity: deepsys_types::Severity,
        pub description: String,
    }

    impl SecretHandler {
        pub fn new() -> Self {
            Self {
                rules: Self::default_secret_rules(),
                enabled: true,
            }
        }

        pub fn with_rules(mut self, rules: Vec<SecretRule>) -> Self {
            self.rules = rules;
            self
        }

        pub fn enabled(mut self, enabled: bool) -> Self {
            self.enabled = enabled;
            self
        }

        fn default_secret_rules() -> Vec<SecretRule> {
            vec![
                SecretRule {
                    id: "aws-access-key".to_string(),
                    name: "AWS Access Key".to_string(),
                    pattern: regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                    severity: deepsys_types::Severity::High,
                    description: "AWS Access Key ID found".to_string(),
                },
                SecretRule {
                    id: "github-token".to_string(),
                    name: "GitHub Token".to_string(),
                    pattern: regex::Regex::new(r"ghp_[0-9A-Za-z]{36}").unwrap(),
                    severity: deepsys_types::Severity::High,
                    description: "GitHub Personal Access Token found".to_string(),
                },
                SecretRule {
                    id: "generic-api-key".to_string(),
                    name: "Generic API Key".to_string(),
                    pattern: regex::Regex::new(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?").unwrap(),
                    severity: deepsys_types::Severity::Medium,
                    description: "Generic API key found".to_string(),
                },
            ]
        }
    }

    #[async_trait]
    impl Handler for SecretHandler {
        fn handler_type(&self) -> HandlerType {
            HandlerType::Secret
        }

        async fn handle(&self, info: &ArtifactInfo) -> Result<HandlerResult> {
            let mut result = HandlerResult::new();
            let start_time = std::time::Instant::now();

            if !self.enabled {
                return Ok(result);
            }

            // Check config files for secrets
            for config_file in &info.config_files {
                for rule in &self.rules {
                    if let Some(secret) = self.check_file_for_secret(config_file, rule).await? {
                        result.add_issue(SecurityIssue::Secret(secret));
                    }
                }
            }

            result.stats.processing_time = start_time.elapsed();
            result.stats.items_processed = info.config_files.len();

            Ok(result)
        }
    }

    impl SecretHandler {
        async fn check_file_for_secret(&self, config_file: &crate::ConfigFile, rule: &SecretRule) -> Result<Option<Secret>> {
            // Simple regex-based secret detection
            for (line_num, line) in config_file.content.lines().enumerate() {
                if rule.pattern.is_match(line) {
                    return Ok(Some(Secret {
                        rule_id: rule.id.clone(),
                        title: rule.name.clone(),
                        severity: rule.severity.clone(),
                        start_line: line_num + 1,
                        end_line: line_num + 1,
                        start_column: 0, // Would need more sophisticated parsing
                        end_column: line.len(),
                        match: rule.pattern.find(line).unwrap().as_str().to_string(),
                        file_path: config_file.path.clone(),
                        entropy: None,
                        custom_fields: std::collections::HashMap::new(),
                    }));
                }
            }

            Ok(None)
        }
    }
}

/// Custom handler for extensibility
pub mod custom {
    use super::*;

    /// Custom handler with user-defined logic
    pub struct CustomHandler {
        handler_type: HandlerType,
        processor: Box<dyn Fn(&ArtifactInfo) -> Result<HandlerResult> + Send + Sync>,
    }

    impl CustomHandler {
        pub fn new<F>(handler_type: HandlerType, processor: F) -> Self
        where
            F: Fn(&ArtifactInfo) -> Result<HandlerResult> + Send + Sync + 'static,
        {
            Self {
                handler_type,
                processor: Box::new(processor),
            }
        }
    }

    #[async_trait]
    impl Handler for CustomHandler {
        fn handler_type(&self) -> HandlerType {
            self.handler_type.clone()
        }

        async fn handle(&self, info: &ArtifactInfo) -> Result<HandlerResult> {
            (self.processor)(info)
        }
    }
}

/// Handler manager for coordinating multiple handlers
pub struct HandlerManager {
    handlers: Vec<Box<dyn Handler>>,
}

impl HandlerManager {
    /// Create a new handler manager
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Add a handler to the manager
    pub fn add_handler<H: Handler + 'static>(mut self, handler: H) -> Self {
        self.handlers.push(Box::new(handler));
        self
    }

    /// Process artifact with all applicable handlers
    pub async fn process(&self, info: &ArtifactInfo) -> Result<Vec<HandlerResult>> {
        let mut results = Vec::new();

        for handler in &self.handlers {
            if handler.can_handle(&info.artifact_type) {
                match handler.handle(info).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        tracing::error!("Handler {:?} failed: {}", handler.handler_type(), e);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Get all handler types
    pub fn handler_types(&self) -> Vec<HandlerType> {
        self.handlers.iter().map(|h| h.handler_type()).collect()
    }
}

impl Default for HandlerManager {
    fn default() -> Self {
        Self::new()
            .add_handler(vulnerability_db::VulnerabilityDBHandler::new())
            .add_handler(policy::PolicyHandler::new())
            .add_handler(license::LicenseHandler::new())
            .add_handler(secret::SecretHandler::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vulnerability_db_handler() {
        let handler = vulnerability_db::VulnerabilityDBHandler::new();
        let info = ArtifactInfo {
            schema_version: 1,
            artifact_type: "filesystem".to_string(),
            created_at: chrono::Utc::now(),
            os: None,
            packages: Vec::new(),
            applications: Vec::new(),
            history: Vec::new(),
            config_files: Vec::new(),
            secrets: Vec::new(),
            custom_data: std::collections::HashMap::new(),
        };

        let result = handler.handle(&info).await.unwrap();
        assert_eq!(result.handler_type(), HandlerType::VulnerabilityDB);
    }

    #[test]
    fn test_secret_rule_creation() {
        let rule = secret::SecretRule {
            id: "test-rule".to_string(),
            name: "Test Rule".to_string(),
            pattern: regex::Regex::new(r"test-pattern").unwrap(),
            severity: deepsys_types::Severity::High,
            description: "Test description".to_string(),
        };

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.severity, deepsys_types::Severity::High);
    }

    #[test]
    fn test_handler_manager() {
        let manager = HandlerManager::default();
        let types = manager.handler_types();

        assert!(types.contains(&HandlerType::VulnerabilityDB));
        assert!(types.contains(&HandlerType::Secret));
    }
}
