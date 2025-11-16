//! # Sast - Core Artifact Analysis Engine
//!
//! Sast is the core artifact analysis engine for Deepsys, responsible for
//! inspecting and analyzing various types of targets including container images,
//! filesystems, Git repositories, and Kubernetes manifests.
//!
//! This crate provides the fundamental analysis capabilities that power all
//! security scanning operations in Deepsys.

use anyhow::Result;
use async_trait::async_trait;
use deepsys_types::{ScanTarget, ScanResult, SecurityIssue, Package, PackageIdentifier, PackageType, OS, Application, Layer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod analyzer;
pub mod artifact;
pub mod handler;
pub mod types;
pub mod walker;

/// Configuration options for artifact analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerOptions {
    /// Type of artifact to analyze
    pub artifact_type: deepsys_types::ScanTarget,

    /// Group of analyzers to use (empty in OSS)
    pub analyzer_group: String,

    /// List of disabled analyzers
    pub disabled_analyzers: Vec<analyzer::AnalyzerType>,

    /// List of disabled handlers
    pub disabled_handlers: Vec<types::HandlerType>,

    /// File patterns to include
    pub file_patterns: Vec<String>,

    /// Parallel processing level
    pub parallel: usize,

    /// Disable progress reporting
    pub no_progress: bool,

    /// Allow insecure connections
    pub insecure: bool,

    /// Offline mode (no network access)
    pub offline: bool,

    /// Additional application directories
    pub app_dirs: Vec<String>,

    /// SBOM source files
    pub sbom_sources: Vec<String>,

    /// Rekor server URL for attestation
    pub rekor_url: String,

    /// AWS region for cloud operations
    pub aws_region: String,

    /// AWS endpoint URL
    pub aws_endpoint: String,

    /// Enable file checksum calculation
    pub file_checksum: bool,

    /// Detection priority settings
    pub detection_priority: types::DetectionPriority,
}

impl Default for AnalyzerOptions {
    fn default() -> Self {
        Self {
            artifact_type: deepsys_types::ScanTarget::Filesystem {
                path: ".".to_string(),
                recursive: true,
            },
            analyzer_group: String::new(),
            disabled_analyzers: Vec::new(),
            disabled_handlers: Vec::new(),
            file_patterns: Vec::new(),
            parallel: num_cpus::get(),
            no_progress: false,
            insecure: false,
            offline: false,
            app_dirs: Vec::new(),
            sbom_sources: Vec::new(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            aws_region: "us-east-1".to_string(),
            aws_endpoint: String::new(),
            file_checksum: false,
            detection_priority: types::DetectionPriority::Comprehensive,
        }
    }
}

/// Artifact represents a target that can be analyzed
#[async_trait]
pub trait Artifact: Send + Sync {
    /// Inspect the artifact and gather information
    async fn inspect(&self) -> Result<ArtifactInfo>;

    /// Clean up any resources used by the artifact
    async fn cleanup(&self) -> Result<()>;
}

/// Information gathered from artifact inspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    /// Schema version
    pub schema_version: u32,

    /// Artifact type
    pub artifact_type: String,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Operating system information
    pub os: Option<deepsys_types::OS>,

    /// Package information
    pub packages: deepsys_types::Packages,

    /// Application information
    pub applications: Vec<deepsys_types::Application>,

    /// History information
    pub history: Vec<History>,

    /// Configuration files
    pub config_files: Vec<ConfigFile>,

    /// Secret findings
    pub secrets: Vec<SecretInfo>,

    /// Custom data
    pub custom_data: HashMap<String, String>,
}

/// History information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    pub created: Option<u64>,
    pub created_by: Option<String>,
    pub comment: Option<String>,
    pub empty_layer: bool,
}

/// Configuration file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub path: String,
    pub content: String,
    pub permissions: Option<u32>,
    pub size: u64,
}

/// Secret information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInfo {
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub length: usize,
    pub entropy: Option<f64>,
    pub rule_id: String,
}

/// Layer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub digest: String,
    pub diff_id: String,
    pub size: u64,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_by: Option<String>,
}

/// Artifact analysis engine
pub struct Analyzer {
    options: AnalyzerOptions,
    analyzers: Vec<Box<dyn analyzer::Analyzer>>,
    handlers: Vec<Box<dyn handler::Handler>>,
}

impl Analyzer {
    /// Create a new analyzer with the given options
    pub fn new(options: AnalyzerOptions) -> Self {
        Self {
            options,
            analyzers: Vec::new(),
            handlers: Vec::new(),
        }
    }

    /// Add an analyzer to the engine
    pub fn add_analyzer<A: analyzer::Analyzer + 'static>(mut self, analyzer: A) -> Self {
        self.analyzers.push(Box::new(analyzer));
        self
    }

    /// Add a handler to the engine
    pub fn add_handler<H: handler::Handler + 'static>(mut self, handler: H) -> Self {
        self.handlers.push(Box::new(handler));
        self
    }

    /// Analyze the configured artifact
    pub async fn analyze(&self) -> Result<ArtifactInfo> {
        info!("Starting artifact analysis for target: {:?}", self.options.artifact_type);

        let mut info = ArtifactInfo {
            schema_version: 1,
            artifact_type: format!("{:?}", self.options.artifact_type),
            created_at: chrono::Utc::now(),
            os: None,
            packages: deepsys_types::Packages::default(),
            applications: Vec::new(),
            history: Vec::new(),
            config_files: Vec::new(),
            secrets: Vec::new(),
            custom_data: HashMap::new(),
        };

        // Run all analyzers
        for analyzer in &self.analyzers {
            match analyzer.analyze(&std::path::Path::new(".")).await {
                Ok(result) => {
                    // Merge OS information
                    if info.os.is_none() && result.os.is_some() {
                        info.os = result.os;
                    }

                    // Merge packages
                    info.packages.packages.extend(result.packages);

                    // Merge applications
                    info.applications.extend(result.applications);

                    // Merge dependencies
                    if !result.dependencies.is_empty() {
                        info.custom_data.insert("dependencies".to_string(),
                            serde_json::to_string(&result.dependencies)?);
                    }

                    // Merge custom data
                    for (key, value) in result.custom_data {
                        info.custom_data.insert(key, value);
                    }
                }
                Err(e) => {
                    warn!("Analyzer {:?} failed: {}", analyzer.analyzer_type(), e);
                }
            }
        }

        debug!("Artifact analysis completed. Found {} packages", info.packages.len());

        // Run handlers for additional processing
        for handler in &self.handlers {
            if let Err(e) = handler.handle(&info).await {
                warn!("Handler failed: {}", e);
            }
        }

        Ok(info)
    }

    /// Create the appropriate artifact based on the target type
    async fn create_artifact(&self) -> Result<Box<dyn Artifact>> {
        match &self.options.artifact_type {
            deepsys_types::ScanTarget::Image { name, .. } => {
                Ok(Box::new(artifact::ImageArtifact::new(name.clone()).await?))
            }
            deepsys_types::ScanTarget::Filesystem { path, .. } => {
                Ok(Box::new(artifact::FilesystemArtifact::new(path.clone()).await?))
            }
            deepsys_types::ScanTarget::Repository { url, .. } => {
                Ok(Box::new(artifact::RepositoryArtifact::new(url.clone()).await?))
            }
            deepsys_types::ScanTarget::Kubernetes { path, .. } => {
                Ok(Box::new(artifact::KubernetesArtifact::new(path.clone()).await?))
            }
            _ => Err(anyhow::anyhow!("Unsupported artifact type")),
        }
    }
}

/// Factory function to create a configured analyzer
pub fn create_analyzer(options: AnalyzerOptions) -> Analyzer {
    let mut analyzer = Analyzer::new(options);

    // Add default analyzers based on target type
    match &analyzer.options.artifact_type {
        deepsys_types::ScanTarget::Image { .. } => {
            // Add image-specific analyzers
            analyzer = analyzer
                .add_analyzer(analyzer::os::OsAnalyzer::new())
                .add_analyzer(analyzer::package::PackageAnalyzer::new())
                .add_analyzer(analyzer::language::LanguageAnalyzer::new());
        }
        deepsys_types::ScanTarget::Filesystem { .. } => {
            // Add filesystem-specific analyzers
            analyzer = analyzer
                .add_analyzer(analyzer::os::OsAnalyzer::new())
                .add_analyzer(analyzer::package::PackageAnalyzer::new())
                .add_analyzer(analyzer::language::LanguageAnalyzer::new())
                .add_analyzer(analyzer::secret::SecretAnalyzer::new());
        }
        deepsys_types::ScanTarget::Repository { .. } => {
            // Add repository-specific analyzers
            analyzer = analyzer
                .add_analyzer(analyzer::package::PackageAnalyzer::new())
                .add_analyzer(analyzer::language::LanguageAnalyzer::new());
        }
        deepsys_types::ScanTarget::Kubernetes { .. } => {
            // Add Kubernetes-specific analyzers
            analyzer = analyzer
                .add_analyzer(analyzer::k8s::KubernetesAnalyzer::new())
                .add_analyzer(analyzer::misconfig::MisconfigurationAnalyzer::new());
        }
        _ => {
            // Add general-purpose analyzers
            analyzer = analyzer
                .add_analyzer(analyzer::package::PackageAnalyzer::new())
                .add_analyzer(analyzer::language::LanguageAnalyzer::new());
        }
    }

    analyzer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyzer_creation() {
        let options = AnalyzerOptions::default();
        let analyzer = create_analyzer(options);

        assert!(!analyzer.analyzers.is_empty());
    }

    #[test]
    fn test_analyzer_options_default() {
        let options = AnalyzerOptions::default();

        assert_eq!(options.parallel, num_cpus::get());
        assert!(!options.offline);
        assert!(!options.insecure);
    }
}
