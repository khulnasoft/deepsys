//! # Misconfiguration Scanner
//!
//! High-level scanner that coordinates all misconfiguration detection
//! and provides the main interface for scanning different target types.

use anyhow::Result;
use deepsys_types::{SecurityIssue, ScanTarget};
use std::sync::Arc;
use tracing::{info, debug, warn};

use crate::{MisconfConfig, MisconfScanner, detector::Detector};

/// High-level misconfiguration scan engine
pub struct MisconfScanEngine {
    config: MisconfConfig,
    scanner: MisconfScanner,
    detectors: Vec<Box<dyn Detector>>,
}

impl MisconfScanEngine {
    /// Create a new scan engine
    pub async fn new(config: MisconfConfig) -> Result<Self> {
        info!("Initializing misconfiguration scan engine");

        let scanner = MisconfScanner::new(config.clone()).await?;
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

        // Add built-in detectors
        detectors.push(Box::new(crate::k8s::K8sDetector::new().await?));
        detectors.push(Box::new(crate::docker::DockerDetector::new().await?));
        detectors.push(Box::new(crate::iac::IacDetector::new().await?));
        detectors.push(Box::new(crate::detector::FilePatternDetector::new(config.clone(), scanner.policies.clone())));

        info!("Misconfiguration scan engine initialized with {} detectors", detectors.len());

        Ok(Self {
            config,
            scanner,
            detectors,
        })
    }

    /// Scan a target for misconfigurations
    pub async fn scan(&self, target: ScanTarget) -> Result<MisconfScanResult> {
        info!("Starting comprehensive misconfiguration scan for target: {:?}", target);

        let scan_start = std::time::Instant::now();
        let mut all_misconfigs = Vec::new();

        match target {
            ScanTarget::Filesystem { path, recursive: _ } => {
                let misconfigs = self.scan_filesystem(&path).await?;
                all_misconfigs.extend(misconfigs);
            }
            ScanTarget::Image { name, .. } => {
                // For container images, we would need to extract filesystem first
                warn!("Misconfiguration scanning for images requires filesystem extraction");
            }
            ScanTarget::Repository { url, .. } => {
                // For repositories, we would need to clone and scan
                warn!("Misconfiguration scanning for repositories not yet implemented");
            }
            ScanTarget::Kubernetes { path, .. } => {
                let misconfigs = self.scan_kubernetes_path(&path).await?;
                all_misconfigs.extend(misconfigs);
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

        // Create scan summary
        let summary = self.create_scan_summary(&filtered_misconfigs);

        info!("Misconfiguration scan completed in {:?}. Found {} issues", scan_duration, filtered_misconfigs.len());

        Ok(MisconfScanResult {
            target,
            misconfigurations: filtered_misconfigs,
            summary,
            scan_duration,
            scanned_at: chrono::Utc::now(),
        })
    }

    /// Scan filesystem for misconfigurations
    async fn scan_filesystem(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        if self.config.parallel && self.config.workers > 1 {
            misconfigs = self.scan_filesystem_parallel(root_path).await?;
        } else {
            misconfigs = self.scan_filesystem_sequential(root_path).await?;
        }

        Ok(misconfigs)
    }

    /// Sequential filesystem scanning
    async fn scan_filesystem_sequential(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for entry in walkdir::WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                for detector in &self.detectors {
                    if detector.can_handle(file_path) {
                        if let Ok(file_misconfigs) = detector.scan_file(file_path).await {
                            misconfigs.extend(file_misconfigs);
                        }
                    }
                }
            }
        }

        Ok(misconfigs)
    }

    /// Parallel filesystem scanning
    async fn scan_filesystem_parallel(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        // Collect all file paths first
        let file_paths: Vec<std::path::PathBuf> = walkdir::WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        debug!("Scanning {} files in parallel", file_paths.len());

        // Use parallel processing
        let results: Result<Vec<Vec<SecurityIssue>>> = tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;

            Ok(file_paths
                .par_iter()
                .map(|file_path| {
                    let mut file_misconfigs = Vec::new();

                    for detector in &self.detectors {
                        if detector.can_handle(file_path) {
                            // Note: This would need async handling in parallel context
                            // For now, using a simplified approach
                            if let Ok(misconfigs) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                // Would need async runtime here
                                Ok::<Vec<SecurityIssue>, anyhow::Error>(Vec::new())
                            })) {
                                file_misconfigs.extend(misconfigs.unwrap_or_default());
                            }
                        }
                    }

                    file_misconfigs
                })
                .collect())
        }).await?;

        let all_results = results?;
        Ok(all_results.into_iter().flatten().collect())
    }

    /// Scan Kubernetes-specific path
    async fn scan_kubernetes_path(&self, path: &str) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for detector in &self.detectors {
            if detector.name().contains("k8s") || detector.name().contains("kubernetes") {
                if let Ok(detector_misconfigs) = detector.scan_file(std::path::Path::new(path)).await {
                    misconfigs.extend(detector_misconfigs);
                }
            }
        }

        Ok(misconfigs)
    }

    /// Create scan summary
    fn create_scan_summary(&self, misconfigs: &[SecurityIssue]) -> MisconfScanSummary {
        let mut summary = MisconfScanSummary {
            total_misconfigurations: misconfigs.len(),
            by_severity: std::collections::HashMap::new(),
            by_category: std::collections::HashMap::new(),
            by_detector: std::collections::HashMap::new(),
            critical_issues: 0,
            high_issues: 0,
            medium_issues: 0,
            low_issues: 0,
        };

        for issue in misconfigs {
            if let SecurityIssue::Misconfiguration(misconf) = issue {
                // Count by severity
                *summary.by_severity.entry(misconf.severity.clone()).or_insert(0) += 1;

                // Count by category
                *summary.by_category.entry(misconf.resource_type.clone().unwrap_or("unknown".to_string())).or_insert(0) += 1;

                // Count by detector (simplified)
                *summary.by_detector.entry("general".to_string()).or_insert(0) += 1;

                // Count by severity level
                match misconf.severity {
                    deepsys_types::Severity::Critical => summary.critical_issues += 1,
                    deepsys_types::Severity::High => summary.high_issues += 1,
                    deepsys_types::Severity::Medium => summary.medium_issues += 1,
                    deepsys_types::Severity::Low => summary.low_issues += 1,
                    deepsys_types::Severity::Info => {},
                    deepsys_types::Severity::Unknown => {},
                }
            }
        }

        summary
    }

    /// Get scan engine statistics
    pub fn get_stats(&self) -> EngineStats {
        EngineStats {
            detectors_count: self.detectors.len(),
            enabled: self.config.enabled,
            parallel_enabled: self.config.parallel,
            workers: self.config.workers,
            policies_count: self.scanner.policies.len(),
        }
    }
}

/// Result of a misconfiguration scan
#[derive(Debug, Clone)]
pub struct MisconfScanResult {
    /// Target that was scanned
    pub target: ScanTarget,

    /// Misconfigurations found
    pub misconfigurations: Vec<SecurityIssue>,

    /// Scan summary
    pub summary: MisconfScanSummary,

    /// Scan duration
    pub scan_duration: std::time::Duration,

    /// Timestamp when scan was performed
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

/// Summary of misconfiguration scan results
#[derive(Debug, Clone)]
pub struct MisconfScanSummary {
    /// Total misconfigurations found
    pub total_misconfigurations: usize,

    /// Misconfigurations by severity
    pub by_severity: std::collections::HashMap<deepsys_types::Severity, usize>,

    /// Misconfigurations by category
    pub by_category: std::collections::HashMap<String, usize>,

    /// Misconfigurations by detector
    pub by_detector: std::collections::HashMap<String, usize>,

    /// Critical severity issues
    pub critical_issues: usize,

    /// High severity issues
    pub high_issues: usize,

    /// Medium severity issues
    pub medium_issues: usize,

    /// Low severity issues
    pub low_issues: usize,
}

/// Scan engine statistics
#[derive(Debug, Clone)]
pub struct EngineStats {
    /// Number of detectors
    pub detectors_count: usize,

    /// Whether scanning is enabled
    pub enabled: bool,

    /// Whether parallel processing is enabled
    pub parallel_enabled: bool,

    /// Number of worker threads
    pub workers: usize,

    /// Number of policies loaded
    pub policies_count: usize,
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
    pub fn with_policy_file(mut self, policy_path: std::path::PathBuf) -> Self {
        self.config.policies.push(policy_path);
        self
    }

    /// Add policy directory
    pub fn with_policy_directory(mut self, policy_dir: std::path::PathBuf) -> Self {
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
    pub fn with_severity_threshold(mut self, severity: deepsys_types::Severity) -> Self {
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
    pub async fn build(self) -> Result<MisconfScanEngine> {
        MisconfScanEngine::new(self.config).await
    }
}

impl Default for MisconfScanBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Misconfiguration scan reporter
pub struct MisconfScanReporter;

impl MisconfScanReporter {
    /// Generate a text report of scan results
    pub fn generate_text_report(result: &MisconfScanResult) -> String {
        let mut report = String::new();

        report.push_str("Misconfiguration Scan Report\n");
        report.push_str("============================\n\n");

        report.push_str(&format!("Target: {:?}\n", result.target));
        report.push_str(&format!("Scanned At: {}\n", result.scanned_at));
        report.push_str(&format!("Duration: {:?}\n", result.scan_duration));
        report.push_str(&format!("Total Misconfigurations Found: {}\n", result.summary.total_misconfigurations));
        report.push_str(&format!("Critical: {}\n", result.summary.critical_issues));
        report.push_str(&format!("High: {}\n", result.summary.high_issues));
        report.push_str(&format!("Medium: {}\n", result.summary.medium_issues));
        report.push_str(&format!("Low: {}\n", result.summary.low_issues));
        report.push_str("\n");

        if !result.summary.by_severity.is_empty() {
            report.push_str("Misconfigurations by Severity:\n");
            for (severity, count) in &result.summary.by_severity {
                report.push_str(&format!("  {}: {}\n", severity.as_str(), count));
            }
            report.push_str("\n");
        }

        if !result.summary.by_category.is_empty() {
            report.push_str("Misconfigurations by Category:\n");
            for (category, count) in &result.summary.by_category {
                report.push_str(&format!("  {}: {}\n", category, count));
            }
            report.push_str("\n");
        }

        if !result.misconfigurations.is_empty() {
            report.push_str("Misconfigurations Found:\n");
            for (i, misconfig) in result.misconfigurations.iter().enumerate() {
                if let SecurityIssue::Misconfiguration(misconf) = misconfig {
                    report.push_str(&format!("  {}. {} ({})\n", i + 1, misconf.title, misconf.id));
                    report.push_str(&format!("     File: {}\n", misconf.file_path));
                    report.push_str(&format!("     Severity: {}\n", misconf.severity.as_str()));
                    report.push_str(&format!("     Description: {}\n", misconf.description));
                    if !misconf.resolution.is_empty() {
                        report.push_str(&format!("     Resolution: {}\n", misconf.resolution));
                    }
                    report.push_str("\n");
                }
            }
        }

        report
    }

    /// Generate a JSON report of scan results
    pub fn generate_json_report(result: &MisconfScanResult) -> Result<String> {
        Ok(serde_json::to_string_pretty(result)?)
    }

    /// Generate a summary report
    pub fn generate_summary_report(result: &MisconfScanResult) -> String {
        format!(
            "Misconfiguration Scan Summary:\n\
             - Target: {:?}\n\
             - Duration: {:?}\n\
             - Total Issues: {}\n\
             - Critical: {}\n\
             - High: {}\n\
             - Medium: {}\n\
             - Low: {}",
            result.target,
            result.scan_duration,
            result.summary.total_misconfigurations,
            result.summary.critical_issues,
            result.summary.high_issues,
            result.summary.medium_issues,
            result.summary.low_issues
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_engine_creation() {
        let config = MisconfConfig::default();
        let engine = MisconfScanEngine::new(config).await;

        assert!(engine.is_ok());

        if let Ok(engine) = engine {
            let stats = engine.get_stats();
            assert!(stats.enabled);
            assert!(stats.detectors_count > 0);
        }
    }

    #[test]
    fn test_scan_builder() {
        let builder = MisconfScanBuilder::new()
            .enabled(true)
            .with_k8s(true)
            .with_docker(true)
            .with_severity_threshold(deepsys_types::Severity::Medium);

        assert!(builder.config.enabled);
        assert!(builder.config.enable_k8s);
        assert!(builder.config.enable_docker);
        assert_eq!(builder.config.severity_threshold, deepsys_types::Severity::Medium);
    }

    #[test]
    fn test_scan_summary_creation() {
        let misconfigs = vec![
            SecurityIssue::Misconfiguration(crate::Misconfiguration {
                id: "test-1".to_string(),
                title: "Test Misconfiguration 1".to_string(),
                description: "Test description 1".to_string(),
                severity: deepsys_types::Severity::High,
                resolution: "Test resolution".to_string(),
                references: Vec::new(),
                file_path: "test.yaml".to_string(),
                line_range: None,
                resource_type: Some("Kubernetes".to_string()),
                resource_name: None,
                custom_fields: std::collections::HashMap::new(),
            }),
            SecurityIssue::Misconfiguration(crate::Misconfiguration {
                id: "test-2".to_string(),
                title: "Test Misconfiguration 2".to_string(),
                description: "Test description 2".to_string(),
                severity: deepsys_types::Severity::Critical,
                resolution: "Test resolution".to_string(),
                references: Vec::new(),
                file_path: "test.tf".to_string(),
                line_range: None,
                resource_type: Some("Terraform".to_string()),
                resource_name: None,
                custom_fields: std::collections::HashMap::new(),
            }),
        ];

        let engine = MisconfScanEngine {
            config: MisconfConfig::default(),
            scanner: MisconfScanner::new(MisconfConfig::default()).await.unwrap(),
            detectors: Vec::new(),
        };

        let summary = engine.create_scan_summary(&misconfigs);

        assert_eq!(summary.total_misconfigurations, 2);
        assert_eq!(summary.critical_issues, 1);
        assert_eq!(summary.high_issues, 1);
        assert_eq!(summary.by_severity[&deepsys_types::Severity::Critical], 1);
        assert_eq!(summary.by_severity[&deepsys_types::Severity::High], 1);
    }
}
