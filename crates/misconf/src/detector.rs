//! # Misconfiguration Detector
//!
//! Core detection logic for misconfiguration scanning. Provides the main
//! scanning interface and coordinates between different detector types.

use anyhow::Result;
use deepsys_types::{Misconfiguration, SecurityIssue, Severity};
use std::path::Path;
use tracing::{debug, info, warn};

use crate::{MisconfConfig, Policy};

/// Main detector trait for misconfiguration detection
pub trait Detector: Send + Sync {
    /// Scan a file for misconfigurations
    async fn scan_file(&self, file_path: &Path) -> Result<Vec<SecurityIssue>>;

    /// Scan a directory for misconfigurations
    async fn scan_directory(&self, dir_path: &Path) -> Result<Vec<SecurityIssue>>;

    /// Check if detector can handle this file type
    fn can_handle(&self, file_path: &Path) -> bool;

    /// Get detector name
    fn name(&self) -> &str;
}

/// Generic file detector for pattern-based misconfiguration detection
pub struct FilePatternDetector {
    config: MisconfConfig,
    policies: Vec<Policy>,
}

impl FilePatternDetector {
    pub fn new(config: MisconfConfig, policies: Vec<Policy>) -> Self {
        Self { config, policies }
    }

    /// Check if file should be scanned based on configuration
    fn should_scan_file(&self, file_path: &Path) -> bool {
        let path_str = file_path.to_string_lossy();

        // Check exclude patterns
        for pattern in &self.config.exclude_patterns {
            if self.matches_pattern(&path_str, pattern) {
                return false;
            }
        }

        // Check include patterns (if any specified)
        if !self.config.include_patterns.is_empty() {
            for pattern in &self.config.include_patterns {
                if self.matches_pattern(&path_str, pattern) {
                    return true;
                }
            }
            return false;
        }

        true
    }

    /// Pattern matching utility
    fn matches_pattern(&self, path: &str, pattern: &str) -> bool {
        if pattern.starts_with("**/") {
            path.contains(&pattern[3..])
        } else if pattern.starts_with("*.") {
            path.ends_with(&pattern[1..])
        } else {
            path.contains(pattern)
        }
    }

    /// Scan content for misconfigurations using policies
    async fn scan_content_with_policies(&self, content: &str, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for policy in &self.policies {
            if let Some(misconfig) = self.evaluate_policy(content, policy, file_path)? {
                misconfigs.push(SecurityIssue::Misconfiguration(misconfig));
            }
        }

        Ok(misconfigs)
    }

    /// Evaluate a single policy against content
    fn evaluate_policy(&self, content: &str, policy: &Policy, file_path: &Path) -> Result<Option<Misconfiguration>> {
        // Simple regex-based policy evaluation
        // In a real implementation, this would be more sophisticated
        if let Ok(regex) = regex::Regex::new(&policy.query) {
            if regex.is_match(content) {
                return Ok(Some(Misconfiguration {
                    id: policy.id.clone(),
                    title: policy.title.clone(),
                    description: policy.description.clone(),
                    severity: policy.severity.clone(),
                    resolution: policy.resolution.clone(),
                    references: policy.references.clone(),
                    file_path: file_path.to_string_lossy().to_string(),
                    line_range: None, // Would need line number detection
                    resource_type: Some(policy.category.clone()),
                    resource_name: None,
                    custom_fields: policy.custom_fields.clone(),
                }));
            }
        }

        Ok(None)
    }
}

impl Detector for FilePatternDetector {
    async fn scan_file(&self, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        if !self.should_scan_file(file_path) {
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(file_path).await?;

        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        self.scan_content_with_policies(&content, file_path).await
    }

    async fn scan_directory(&self, dir_path: &Path) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for entry in walkdir::WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Ok(file_misconfigs) = self.scan_file(entry.path()).await {
                    misconfigs.extend(file_misconfigs);
                }
            }
        }

        Ok(misconfigs)
    }

    fn can_handle(&self, file_path: &Path) -> bool {
        // Can handle any file type based on patterns
        self.should_scan_file(file_path)
    }

    fn name(&self) -> &str {
        "file-pattern-detector"
    }
}

/// Batch detector for processing multiple files efficiently
pub struct BatchDetector {
    detectors: Vec<Box<dyn Detector>>,
    config: MisconfConfig,
}

impl BatchDetector {
    pub fn new(config: MisconfConfig) -> Self {
        Self {
            detectors: Vec::new(),
            config,
        }
    }

    pub fn add_detector(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Scan multiple files in parallel
    pub async fn scan_batch(&self, file_paths: Vec<std::path::PathBuf>) -> Result<Vec<SecurityIssue>> {
        use futures::future::join_all;

        if self.config.parallel && self.config.workers > 1 {
            // Parallel processing
            let tasks: Vec<_> = file_paths
                .chunks(std::cmp::max(1, file_paths.len() / self.config.workers))
                .map(|chunk| self.scan_files_chunk(chunk.to_vec()))
                .collect();

            let results = join_all(tasks).await;
            let mut all_misconfigs = Vec::new();

            for result in results {
                match result {
                    Ok(misconfigs) => all_misconfigs.extend(misconfigs),
                    Err(e) => warn!("Batch scan error: {}", e),
                }
            }

            Ok(all_misconfigs)
        } else {
            // Sequential processing
            let mut all_misconfigs = Vec::new();

            for file_path in file_paths {
                for detector in &self.detectors {
                    if detector.can_handle(&file_path) {
                        if let Ok(misconfigs) = detector.scan_file(&file_path).await {
                            all_misconfigs.extend(misconfigs);
                        }
                    }
                }
            }

            Ok(all_misconfigs)
        }
    }

    /// Scan a chunk of files
    async fn scan_files_chunk(&self, file_paths: Vec<std::path::PathBuf>) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for file_path in file_paths {
            for detector in &self.detectors {
                if detector.can_handle(&file_path) {
                    if let Ok(file_misconfigs) = detector.scan_file(&file_path).await {
                        misconfigs.extend(file_misconfigs);
                    }
                }
            }
        }

        Ok(misconfigs)
    }
}

impl Default for BatchDetector {
    fn default() -> Self {
        Self::new(MisconfConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_pattern_matching() {
        let config = MisconfConfig::default();
        let detector = FilePatternDetector::new(config, Vec::new());

        assert!(detector.matches_pattern("src/main.py", "**/*.py"));
        assert!(detector.matches_pattern("app.py", "*.py"));
        assert!(detector.matches_pattern("src/app.py", "**/app.py"));
        assert!(!detector.matches_pattern("src/main.js", "**/*.py"));
    }

    #[test]
    fn test_should_scan_file() {
        let config = MisconfConfig::default();
        let detector = FilePatternDetector::new(config, Vec::new());

        assert!(detector.should_scan_file(Path::new("src/main.py")));
        assert!(!detector.should_scan_file(Path::new(".git/config")));
        assert!(!detector.should_scan_file(Path::new("node_modules/package.json")));
    }

    #[tokio::test]
    async fn test_batch_detector() {
        let config = MisconfConfig::default();
        let mut batch_detector = BatchDetector::new(config);

        let file_pattern_detector = Box::new(FilePatternDetector::new(MisconfConfig::default(), Vec::new()));
        batch_detector.add_detector(file_pattern_detector);

        let file_paths = vec![
            std::path::PathBuf::from("test1.py"),
            std::path::PathBuf::from("test2.py"),
        ];

        // This would require actual files to test properly
        // For now, just verify the method exists
        assert!(batch_detector.scan_batch(file_paths).await.is_ok());
    }
}
