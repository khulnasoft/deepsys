//! # Deepsys CLI
//!
//! Command-line interface for the Deepsys security scanner.
//! Provides commands for scanning various targets and generating reports.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use deepsys_types::{ScanTarget, Severity};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, error};

/// Deepsys - A modern security scanner
#[derive(Parser)]
#[command(name = "deepsys")]
#[command(about = "A modern security scanner for containers and filesystems")]
#[command(version, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase verbosity (can be used multiple times: -v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Decrease verbosity
    #[arg(short, long)]
    pub quiet: bool,

    /// Configuration file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "table")]
    pub format: OutputFormat,

    /// Output file
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan for vulnerabilities
    Scan {
        /// Target to scan (image, filesystem path, etc.)
        #[arg(value_name = "TARGET")]
        target: String,

        /// Scanner types to use
        #[arg(short, long, value_enum, default_values = ["vuln", "secret", "misconfig"])]
        scanners: Vec<ScannerType>,

        /// Skip policy checks
        #[arg(long)]
        skip_policy: bool,

        /// Skip database updates
        #[arg(long)]
        skip_update: bool,

        /// Parallel processing level
        #[arg(short = 'j', long, default_value = "1")]
        parallel: usize,
    },

    /// Generate SBOM (Software Bill of Materials)
    Sbom {
        /// Target to analyze
        #[arg(value_name = "TARGET")]
        target: String,

        /// SBOM format
        #[arg(short, long, default_value = "cyclonedx")]
        format: SbomFormat,
    },

    /// Show version information
    Version,

    /// Update vulnerability databases
    Update,

    /// Validate configuration
    Validate,

    /// Show server information
    Server,
}

/// Scanner types
#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize)]
pub enum ScannerType {
    /// Vulnerability scanner
    Vuln,
    /// Secret scanner
    Secret,
    /// Misconfiguration scanner
    Misconfig,
    /// License scanner
    License,
    /// RBAC scanner
    Rbac,
    /// SBOM scanner
    Sbom,
}

impl std::fmt::Display for ScannerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerType::Vuln => write!(f, "vuln"),
            ScannerType::Secret => write!(f, "secret"),
            ScannerType::Misconfig => write!(f, "misconfig"),
            ScannerType::License => write!(f, "license"),
            ScannerType::Rbac => write!(f, "rbac"),
            ScannerType::Sbom => write!(f, "sbom"),
        }
    }
}

/// Output formats
#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Table format
    Table,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// SARIF format
    Sarif,
    /// CycloneDX format
    CycloneDX,
    /// SPDX format
    SPDX,
    /// Template format
    Template,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Yaml => write!(f, "yaml"),
            OutputFormat::Sarif => write!(f, "sarif"),
            OutputFormat::CycloneDX => write!(f, "cyclonedx"),
            OutputFormat::SPDX => write!(f, "spdx"),
            OutputFormat::Template => write!(f, "template"),
        }
    }
}

/// SBOM formats
#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize)]
pub enum SbomFormat {
    /// CycloneDX format
    CycloneDX,
    /// SPDX format
    SPDX,
    /// SPDX JSON format
    SPDXJSON,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomFormat::CycloneDX => write!(f, "cyclonedx"),
            SbomFormat::SPDX => write!(f, "spdx"),
            SbomFormat::SPDXJSON => write!(f, "spdx-json"),
        }
    }
}

/// CLI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Database configuration
    pub database: DatabaseConfig,

    /// Scanning configuration
    pub scanning: ScanningConfig,

    /// Output configuration
    pub output: OutputConfig,

    /// Cache configuration
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Enable database updates
    pub update: bool,

    /// Database URLs
    pub urls: Vec<String>,

    /// Database cache directory
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningConfig {
    /// Default scanners to use
    pub scanners: Vec<ScannerType>,

    /// Parallel processing level
    pub parallel: usize,

    /// Skip policy checks
    pub skip_policy: bool,

    /// File patterns to scan
    pub file_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Default output format
    pub format: OutputFormat,

    /// Output template
    pub template: Option<String>,

    /// Include debug information
    pub debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache directory
    pub dir: Option<PathBuf>,

    /// Cache TTL in seconds
    pub ttl: u64,

    /// Maximum cache size in bytes
    pub max_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: DatabaseConfig {
                update: true,
                urls: vec![
                    "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
                    "https://api.osv.dev/v1".to_string(),
                ],
                cache_dir: Some(PathBuf::from("~/.cache/deepsys/db")),
            },
            scanning: ScanningConfig {
                scanners: vec![ScannerType::Vuln, ScannerType::Secret, ScannerType::Misconfig],
                parallel: num_cpus::get(),
                skip_policy: false,
                file_patterns: Vec::new(),
            },
            output: OutputConfig {
                format: OutputFormat::Table,
                template: None,
                debug: false,
            },
            cache: CacheConfig {
                dir: Some(PathBuf::from("~/.cache/deepsys")),
                ttl: 3600, // 1 hour
                max_size: 1024 * 1024 * 1024, // 1GB
            },
        }
    }
}

impl Cli {
    /// Parse command line arguments
    pub fn parse() -> Self {
        Parser::parse()
    }

    /// Initialize logging based on verbosity level
    pub fn init_logging(&self) {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(match self.verbose {
                0 => tracing::Level::WARN,
                1 => tracing::Level::INFO,
                2 => tracing::Level::DEBUG,
                _ => tracing::Level::TRACE,
            })
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    }

    /// Load configuration
    pub fn load_config(&self) -> Result<Config> {
        if let Some(config_path) = &self.config {
            let content = std::fs::read_to_string(config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    /// Convert scanner types to internal representation
    pub fn convert_scanners(&self, scanners: &[ScannerType]) -> Vec<deepsys_types::Scanner> {
        scanners.iter().map(|s| match s {
            ScannerType::Vuln => deepsys_types::Scanner::Vulnerability,
            ScannerType::Secret => deepsys_types::Scanner::Secret,
            ScannerType::Misconfig => deepsys_types::Scanner::Misconfiguration,
            ScannerType::License => deepsys_types::Scanner::License,
            ScannerType::Rbac => deepsys_types::Scanner::RBAC,
            ScannerType::Sbom => deepsys_types::Scanner::SBOM,
        }).collect()
    }

    /// Execute the CLI command
    pub async fn execute(&self) -> Result<()> {
        self.init_logging();

        match &self.command {
            Commands::Scan { target, scanners, .. } => {
                info!("Starting scan of target: {}", target);
                self.execute_scan(target, scanners).await
            }
            Commands::Sbom { target, format } => {
                info!("Generating SBOM for target: {}", target);
                self.execute_sbom(target, format).await
            }
            Commands::Version => {
                self.execute_version()
            }
            Commands::Update => {
                info!("Updating vulnerability databases");
                self.execute_update().await
            }
            Commands::Validate => {
                info!("Validating configuration");
                self.execute_validate()
            }
            Commands::Server => {
                self.execute_server()
            }
        }
    }

    /// Execute scan command
    async fn execute_scan(&self, target: &str, scanners: &[ScannerType]) -> Result<()> {
        // Parse target
        let scan_target = self.parse_target(target)?;

        // Initialize database manager
        // let mut db_manager = db::create_default_manager().await?;

        // Execute scan
        let mut analyzer = deepsys_sast::create_analyzer(deepsys_sast::AnalyzerOptions {
            artifact_type: scan_target,
            ..Default::default()
        });

        // Add vulnerability database integration
        // let vulnerability_scanner = deepsys_vulnerability::VulnerabilityScanner::new(db_manager);
        // analyzer = analyzer.add_handler(Box::new(vulnerability_scanner));

        // Execute analysis
        match analyzer.analyze().await {
            Ok(result) => {
                self.output_result(&result).await?;
                Ok(())
            }
            Err(e) => {
                error!("Scan failed: {}", e);
                Err(e)
            }
        }
    }

    /// Execute SBOM generation
    async fn execute_sbom(&self, target: &str, format: &SbomFormat) -> Result<()> {
        info!("SBOM generation not yet implemented for target: {}", target);
        Ok(())
    }

    /// Execute version command
    fn execute_version(&self) -> Result<()> {
        println!("Deepsys Security Scanner v{}", env!("CARGO_PKG_VERSION"));
        println!("Built with Rust {}", env!("RUSTC_VERSION"));
        Ok(())
    }

    /// Execute update command
    async fn execute_update(&self) -> Result<()> {
        let db_manager = deepsys_db::create_default_manager().await?;
        db_manager.refresh_all().await?;
        println!("Database update completed");
        Ok(())
    }

    /// Execute validate command
    fn execute_validate(&self) -> Result<()> {
        let config = self.load_config()?;
        println!("Configuration is valid");
        println!("Database URLs: {:?}", config.database.urls);
        println!("Scanners: {:?}", config.scanning.scanners);
        Ok(())
    }

    /// Execute server command
    fn execute_server(&self) -> Result<()> {
        println!("Server mode not yet implemented");
        Ok(())
    }

    /// Parse target string into ScanTarget
    fn parse_target(&self, target: &str) -> Result<ScanTarget> {
        if target.starts_with("docker://") || target.contains(":") {
            // Container image
            Ok(ScanTarget::Image {
                name: target.to_string(),
                registry: None,
                tag: None,
            })
        } else if target.starts_with("http://") || target.starts_with("https://") {
            // Remote URL
            Ok(ScanTarget::Remote {
                url: target.to_string(),
                method: deepsys_types::RemoteMethod::HTTP,
            })
        } else if std::path::Path::new(target).exists() {
            // Filesystem path
            Ok(ScanTarget::Filesystem {
                path: target.to_string(),
                recursive: true,
            })
        } else {
            // Default to filesystem
            Ok(ScanTarget::Filesystem {
                path: target.to_string(),
                recursive: true,
            })
        }
    }

    /// Output scan results
    async fn output_result(&self, result: &deepsys_types::ScanResult) -> Result<()> {
        match self.format {
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(result)?;
                println!("{}", json);
            }
            OutputFormat::Table => {
                self.output_table(result);
            }
            OutputFormat::Yaml => {
                let yaml = serde_yaml::to_string(result)?;
                println!("{}", yaml);
            }
            _ => {
                println!("Output format {:?} not yet implemented", self.format);
            }
        }
        Ok(())
    }

    /// Output results in table format
    fn output_table(&self, result: &deepsys_types::ScanResult) {
        println!("Scan Results");
        println!("============");
        println!("Target: {:?}", result.target);
        println!("Timestamp: {}", result.timestamp);
        println!("Duration: {:?}", result.duration);
        println!();

        println!("Summary:");
        println!("  Total issues: {}", result.summary.total_issues);
        println!("  Critical: {}", result.summary.issues_by_severity.get("CRITICAL").unwrap_or(&0));
        println!("  High: {}", result.summary.issues_by_severity.get("HIGH").unwrap_or(&0));
        println!("  Medium: {}", result.summary.issues_by_severity.get("MEDIUM").unwrap_or(&0));
        println!("  Low: {}", result.summary.issues_by_severity.get("LOW").unwrap_or(&0));
        println!("  Info: {}", result.summary.issues_by_severity.get("INFO").unwrap_or(&0));
        println!();

        if !result.issues.is_empty() {
            println!("Issues:");
            for (i, issue) in result.issues.iter().enumerate() {
                println!("  {}. {} - {}", i + 1, issue.title(), issue.severity());
            }
        }
    }
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.execute().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_type_conversion() {
        let cli = Cli {
            command: Commands::Version,
            verbose: 0,
            quiet: false,
            config: None,
            format: OutputFormat::Table,
            output: None,
        };

        let scanners = vec![ScannerType::Vuln, ScannerType::Secret];
        let converted = cli.convert_scanners(&scanners);

        assert_eq!(converted.len(), 2);
        assert!(matches!(converted[0], deepsys_types::Scanner::Vulnerability));
        assert!(matches!(converted[1], deepsys_types::Scanner::Secret));
    }

    #[test]
    fn test_target_parsing() {
        let cli = Cli {
            command: Commands::Version,
            verbose: 0,
            quiet: false,
            config: None,
            format: OutputFormat::Table,
            output: None,
        };

        // Test image target
        let target = cli.parse_target("nginx:latest").unwrap();
        assert!(matches!(target, ScanTarget::Image { .. }));

        // Test filesystem target
        let target = cli.parse_target("/tmp").unwrap();
        assert!(matches!(target, ScanTarget::Filesystem { .. }));
    }
}
