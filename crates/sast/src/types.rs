//! # Sast Types
//!
//! Sast-specific type definitions and utility types for artifact analysis.

use deepsys_types::{PackageType, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Handler types for different processing operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerType {
    /// Vulnerability database handler
    VulnerabilityDB,
    /// Policy handler
    Policy,
    /// License handler
    License,
    /// Secret handler
    Secret,
    /// Custom handler
    Custom(String),
}

impl std::fmt::Display for HandlerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerType::VulnerabilityDB => write!(f, "vulnerability-db"),
            HandlerType::Policy => write!(f, "policy"),
            HandlerType::License => write!(f, "license"),
            HandlerType::Secret => write!(f, "secret"),
            HandlerType::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// Detection priority levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionPriority {
    /// Comprehensive detection (slowest, most thorough)
    Comprehensive,
    /// High priority detection (balanced)
    High,
    /// Fast detection (fastest, least thorough)
    Fast,
    /// Custom priority with specific settings
    Custom {
        package_detection: bool,
        file_detection: bool,
        secret_detection: bool,
    },
}

impl Default for DetectionPriority {
    fn default() -> Self {
        Self::Comprehensive
    }
}

/// Image options for container analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageOptions {
    /// Registry authentication
    pub registry_auth: Option<RegistryAuth>,
    /// Platform specification
    pub platform: Option<String>,
    /// Skip update check
    pub skip_update: bool,
    /// Timeout duration
    pub timeout: std::time::Duration,
}

impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            registry_auth: None,
            platform: None,
            skip_update: false,
            timeout: std::time::Duration::from_secs(300),
        }
    }
}

/// Registry authentication information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAuth {
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub registry_token: Option<String>,
}

/// File information with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path
    pub path: String,
    /// File size in bytes
    pub size: u64,
    /// File permissions (Unix style)
    pub permissions: Option<u32>,
    /// File type
    pub file_type: FileType,
    /// Last modified time
    pub modified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// MD5 hash
    pub md5_hash: Option<String>,
    /// SHA256 hash
    pub sha256_hash: Option<String>,
    /// MIME type
    pub mime_type: Option<String>,
    /// Extended attributes
    pub extended_attrs: HashMap<String, String>,
}

/// File type classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    /// Regular file
    Regular,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
    /// Block device
    BlockDevice,
    /// Character device
    CharacterDevice,
    /// Named pipe (FIFO)
    Fifo,
    /// Socket
    Socket,
    /// Unknown file type
    Unknown,
}

/// Processing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStats {
    /// Files processed
    pub files_processed: usize,
    /// Directories traversed
    pub directories_traversed: usize,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Processing duration
    pub processing_time: std::time::Duration,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Warnings generated
    pub warnings: Vec<String>,
}

impl Default for ProcessingStats {
    fn default() -> Self {
        Self {
            files_processed: 0,
            directories_traversed: 0,
            bytes_processed: 0,
            processing_time: std::time::Duration::default(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Analysis context for sharing state between analyzers
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Root path being analyzed
    pub root_path: std::path::PathBuf,
    /// Analysis options
    pub options: super::AnalyzerOptions,
    /// Processing statistics
    pub stats: ProcessingStats,
    /// Cache for analysis results
    pub cache: HashMap<String, String>,
    /// Custom context data
    pub custom_data: HashMap<String, String>,
}

impl AnalysisContext {
    /// Create a new analysis context
    pub fn new(root_path: std::path::PathBuf, options: super::AnalyzerOptions) -> Self {
        Self {
            root_path,
            options,
            stats: ProcessingStats::default(),
            cache: HashMap::new(),
            custom_data: HashMap::new(),
        }
    }

    /// Add an error to the statistics
    pub fn add_error(&mut self, error: String) {
        self.stats.errors.push(error);
    }

    /// Add a warning to the statistics
    pub fn add_warning(&mut self, warning: String) {
        self.stats.warnings.push(warning);
    }

    /// Get cached value
    pub fn get_cached(&self, key: &str) -> Option<&String> {
        self.cache.get(key)
    }

    /// Set cached value
    pub fn set_cached(&mut self, key: String, value: String) {
        self.cache.insert(key, value);
    }
}

/// File filter for excluding certain files or directories
#[derive(Debug, Clone)]
pub struct FileFilter {
    /// Patterns to include (empty means include all)
    pub include_patterns: Vec<String>,
    /// Patterns to exclude
    pub exclude_patterns: Vec<String>,
    /// Maximum file size in bytes (0 means no limit)
    pub max_file_size: u64,
    /// Maximum depth to traverse (0 means no limit)
    pub max_depth: usize,
}

impl Default for FileFilter {
    fn default() -> Self {
        Self {
            include_patterns: Vec::new(),
            exclude_patterns: vec![
                "**/.git/**".to_string(),
                "**/node_modules/**".to_string(),
                "**/.DS_Store".to_string(),
                "**/.*".to_string(),
            ],
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_depth: 0, // No limit
        }
    }
}

impl FileFilter {
    /// Check if a path should be included based on the filter rules
    pub fn should_include(&self, path: &std::path::Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns first
        for pattern in &self.exclude_patterns {
            if self.matches_pattern(&path_str, pattern) {
                return false;
            }
        }

        // If include patterns are specified, path must match at least one
        if !self.include_patterns.is_empty() {
            for pattern in &self.include_patterns {
                if self.matches_pattern(&path_str, pattern) {
                    return true;
                }
            }
            return false;
        }

        // Check file size limit
        if let Ok(metadata) = std::fs::metadata(path) {
            if self.max_file_size > 0 && metadata.len() > self.max_file_size {
                return false;
            }
        }

        true
    }

    /// Simple pattern matching (supports * wildcards)
    fn matches_pattern(&self, path: &str, pattern: &str) -> bool {
        if pattern.starts_with("**/") {
            path.contains(&pattern[3..])
        } else if pattern.starts_with("*.") {
            path.ends_with(&pattern[1..])
        } else {
            path.contains(pattern)
        }
    }
}

/// Detection result for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// File path that was analyzed
    pub file_path: String,
    /// Detection timestamp
    pub detected_at: chrono::DateTime<chrono::Utc>,
    /// Analyzer that made the detection
    pub analyzer_type: super::analyzer::AnalyzerType,
    /// Detection confidence (0.0 to 1.0)
    pub confidence: f64,
    /// Detection details
    pub details: HashMap<String, String>,
    /// Issues found
    pub issues: Vec<SecurityIssue>,
}

impl DetectionResult {
    /// Create a new detection result
    pub fn new(
        file_path: String,
        analyzer_type: super::analyzer::AnalyzerType,
        confidence: f64,
    ) -> Self {
        Self {
            file_path,
            detected_at: chrono::Utc::now(),
            analyzer_type,
            confidence,
            details: HashMap::new(),
            issues: Vec::new(),
        }
    }

    /// Add a detail to the detection result
    pub fn add_detail(&mut self, key: String, value: String) {
        self.details.insert(key, value);
    }

    /// Add an issue to the detection result
    pub fn add_issue(&mut self, issue: SecurityIssue) {
        self.issues.push(issue);
    }
}

/// Batch processing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Number of concurrent workers
    pub workers: usize,
    /// Batch size for processing
    pub batch_size: usize,
    /// Timeout per batch
    pub timeout: std::time::Duration,
    /// Retry attempts on failure
    pub retry_attempts: u32,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            workers: num_cpus::get(),
            batch_size: 100,
            timeout: std::time::Duration::from_secs(30),
            retry_attempts: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_filter_default() {
        let filter = FileFilter::default();

        assert!(filter.exclude_patterns.contains(&"**/.git/**".to_string()));
        assert!(filter.exclude_patterns.contains(&"**/node_modules/**".to_string()));
        assert_eq!(filter.max_file_size, 100 * 1024 * 1024);
    }

    #[test]
    fn test_file_filter_should_include() {
        let filter = FileFilter {
            include_patterns: vec!["**/*.rs".to_string()],
            ..Default::default()
        };

        assert!(filter.should_include(std::path::Path::new("src/lib.rs")));
        assert!(!filter.should_include(std::path::Path::new("README.md")));
    }

    #[test]
    fn test_detection_priority_default() {
        let priority = DetectionPriority::default();
        assert_eq!(priority, DetectionPriority::Comprehensive);
    }

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert_eq!(config.workers, num_cpus::get());
        assert_eq!(config.batch_size, 100);
    }
}
