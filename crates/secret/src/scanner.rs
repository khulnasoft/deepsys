//! # Secret Scanner
//!
//! High-level secret scanning interface that coordinates between detectors
//! and provides comprehensive secret detection across multiple file types.

use anyhow::Result;
use deepsys_types::{Secret as DeepSysSecret, SecurityIssue, ScanTarget};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::{SecretConfig, SecretScanner, SecretRule};

/// High-level secret scanning interface
pub struct SecretScanEngine {
    config: SecretConfig,
    scanner: SecretScanner,
}

impl SecretScanEngine {
    /// Create a new secret scan engine
    pub async fn new(config: SecretConfig) -> Result<Self> {
        info!("Initializing secret scan engine");

        let scanner = SecretScanner::new(config.clone()).await?;

        Ok(Self { config, scanner })
    }

    /// Scan a target for secrets
    pub async fn scan(&self, target: ScanTarget) -> Result<SecretScanResult> {
        info!("Starting secret scan for target: {:?}", target);

        let scan_start = std::time::Instant::now();
        let mut all_secrets = Vec::new();

        match target {
            ScanTarget::Filesystem { path, recursive: _ } => {
                let secrets = self.scanner.scan_filesystem(&path).await?;
                all_secrets.extend(secrets);
            }
            ScanTarget::Image { name, .. } => {
                // For container images, we would need to extract filesystem first
                warn!("Secret scanning for container images not yet implemented");
            }
            ScanTarget::Repository { url, .. } => {
                // For repositories, we would need to clone and scan
                warn!("Secret scanning for repositories not yet implemented");
            }
            ScanTarget::Kubernetes { path, .. } => {
                let secrets = self.scanner.scan_kubernetes_manifests(&path).await?;
                all_secrets.extend(secrets);
            }
            _ => {
                warn!("Secret scanning not supported for target type: {:?}", target);
            }
        }

        let scan_duration = scan_start.elapsed();

        // Create scan summary
        let summary = self.create_scan_summary(&all_secrets);

        info!("Secret scan completed in {:?}. Found {} secrets", scan_duration, all_secrets.len());

        Ok(SecretScanResult {
            target,
            secrets: all_secrets,
            summary,
            scan_duration,
            scanned_at: chrono::Utc::now(),
        })
    }

    /// Create scan summary
    fn create_scan_summary(&self, secrets: &[SecurityIssue]) -> SecretScanSummary {
        let mut summary = SecretScanSummary {
            total_secrets: secrets.len(),
            by_severity: HashMap::new(),
            by_rule: HashMap::new(),
            by_file_type: HashMap::new(),
            high_confidence: 0,
            with_validation: 0,
        };

        for secret in secrets {
            if let SecurityIssue::Secret(secret_detail) = secret {
                // Count by severity
                *summary.by_severity.entry(secret_detail.severity.clone()).or_insert(0) += 1;

                // Count by rule
                *summary.by_rule.entry(secret_detail.rule_id.clone()).or_insert(0) += 1;

                // Count by file type
                let file_extension = Path::new(&secret_detail.file_path)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("unknown");
                *summary.by_file_type.entry(file_extension.to_string()).or_insert(0) += 1;

                // Count high confidence
                if secret_detail.custom_fields.get("confidence").map_or(false, |c| c == "high") {
                    summary.high_confidence += 1;
                }

                // Count with validation
                if secret_detail.custom_fields.get("validated").map_or(false, |v| v == "true") {
                    summary.with_validation += 1;
                }
            }
        }

        summary
    }

    /// Get scan engine statistics
    pub fn get_stats(&self) -> EngineStats {
        EngineStats {
            rules_count: self.config.rules.len(),
            enabled: self.config.enabled,
            parallel_enabled: self.config.parallel,
            workers: self.config.workers,
        }
    }
}

/// Result of a secret scan
#[derive(Debug, Clone)]
pub struct SecretScanResult {
    /// Target that was scanned
    pub target: ScanTarget,

    /// Secrets found
    pub secrets: Vec<SecurityIssue>,

    /// Scan summary
    pub summary: SecretScanSummary,

    /// Scan duration
    pub scan_duration: std::time::Duration,

    /// Timestamp when scan was performed
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

/// Summary of secret scan results
#[derive(Debug, Clone)]
pub struct SecretScanSummary {
    /// Total secrets found
    pub total_secrets: usize,

    /// Secrets by severity
    pub by_severity: HashMap<deepsys_types::Severity, usize>,

    /// Secrets by detection rule
    pub by_rule: HashMap<String, usize>,

    /// Secrets by file type
    pub by_file_type: HashMap<String, usize>,

    /// High confidence detections
    pub high_confidence: usize,

    /// Secrets that passed validation
    pub with_validation: usize,
}

/// Scan engine statistics
#[derive(Debug, Clone)]
pub struct EngineStats {
    /// Number of detection rules
    pub rules_count: usize,

    /// Whether scanning is enabled
    pub enabled: bool,

    /// Whether parallel processing is enabled
    pub parallel_enabled: bool,

    /// Number of worker threads
    pub workers: usize,
}

/// Configuration builder for secret scanning
pub struct SecretScanBuilder {
    config: SecretConfig,
}

impl SecretScanBuilder {
    /// Create a new scan builder
    pub fn new() -> Self {
        Self {
            config: SecretConfig::default(),
        }
    }

    /// Enable or disable secret scanning
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Add custom detection rule
    pub fn with_rule(mut self, rule: SecretRule) -> Self {
        self.config.rules.push(rule);
        self
    }

    /// Set entropy threshold
    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.config.entropy_threshold = threshold;
        self
    }

    /// Enable parallel processing
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.config.parallel = enabled;
        self
    }

    /// Set number of worker threads
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.config.workers = workers;
        self
    }

    /// Add include pattern
    pub fn with_include_pattern(mut self, pattern: String) -> Self {
        self.config.include_patterns.push(pattern);
        self
    }

    /// Add exclude pattern
    pub fn with_exclude_pattern(mut self, pattern: String) -> Self {
        self.config.exclude_patterns.push(pattern);
        self
    }

    /// Enable validation
    pub fn with_validation(mut self, enabled: bool) -> Self {
        self.config.enable_validation = enabled;
        self
    }

    /// Build the scan engine
    pub async fn build(self) -> Result<SecretScanEngine> {
        SecretScanEngine::new(self.config).await
    }
}

impl Default for SecretScanBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Secret scan reporter for generating reports
pub struct SecretScanReporter;

impl SecretScanReporter {
    /// Generate a text report of scan results
    pub fn generate_text_report(result: &SecretScanResult) -> String {
        let mut report = String::new();

        report.push_str(&format!("Secret Scan Report\n"));
        report.push_str(&format!("==================\n\n"));

        report.push_str(&format!("Target: {:?}\n", result.target));
        report.push_str(&format!("Scanned At: {}\n", result.scanned_at));
        report.push_str(&format!("Duration: {:?}\n", result.scan_duration));
        report.push_str(&format!("Total Secrets Found: {}\n", result.summary.total_secrets));
        report.push_str("\n");

        if !result.summary.by_severity.is_empty() {
            report.push_str("Secrets by Severity:\n");
            for (severity, count) in &result.summary.by_severity {
                report.push_str(&format!("  {}: {}\n", severity.as_str(), count));
            }
            report.push_str("\n");
        }

        if !result.summary.by_rule.is_empty() {
            report.push_str("Secrets by Rule:\n");
            for (rule, count) in &result.summary.by_rule {
                report.push_str(&format!("  {}: {}\n", rule, count));
            }
            report.push_str("\n");
        }

        if !result.secrets.is_empty() {
            report.push_str("Detected Secrets:\n");
            for (i, secret) in result.secrets.iter().enumerate() {
                if let SecurityIssue::Secret(secret_detail) = secret {
                    report.push_str(&format!("  {}. {} ({})\n", i + 1, secret_detail.title, secret_detail.rule_id));
                    report.push_str(&format!("     File: {}\n", secret_detail.file_path));
                    report.push_str(&format!("     Severity: {}\n", secret_detail.severity.as_str()));
                    if let Some(entropy) = secret_detail.entropy {
                        report.push_str(&format!("     Entropy: {:.2}\n", entropy));
                    }
                    report.push_str("\n");
                }
            }
        }

        report
    }

    /// Generate a JSON report of scan results
    pub fn generate_json_report(result: &SecretScanResult) -> Result<String> {
        Ok(serde_json::to_string_pretty(result)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_summary() {
        let secrets = vec![
            SecurityIssue::Secret(DeepSysSecret {
                rule_id: "test-rule".to_string(),
                title: "Test Secret".to_string(),
                severity: deepsys_types::Severity::High,
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 10,
                match: "secret123".to_string(),
                file_path: "test.py".to_string(),
                entropy: Some(3.5),
                custom_fields: HashMap::new(),
            }),
        ];

        let engine = SecretScanEngine {
            config: SecretConfig::default(),
            scanner: SecretScanner::new(SecretConfig::default()).await.unwrap(),
        };

        let summary = engine.create_scan_summary(&secrets);

        assert_eq!(summary.total_secrets, 1);
        assert_eq!(summary.by_severity[&deepsys_types::Severity::High], 1);
        assert_eq!(summary.by_rule["test-rule"], 1);
    }

    #[tokio::test]
    async fn test_scan_builder() {
        let engine = SecretScanBuilder::new()
            .enabled(true)
            .with_entropy_threshold(3.0)
            .build()
            .await;

        assert!(engine.is_ok());

        if let Ok(engine) = engine {
            let stats = engine.get_stats();
            assert!(stats.enabled);
            assert!(stats.rules_count > 0);
        }
    }
}
