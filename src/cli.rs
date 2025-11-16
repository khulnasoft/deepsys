use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, error};

/// Deep security scanner - Rust implementation of Deepsys
#[derive(Parser)]
#[command(name = "deepsys")]
#[command(about = "A comprehensive security scanner")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable debug output
    #[arg(short, long)]
    debug: bool,

    /// Output format (json, yaml, table)
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Output file
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan container images
    Image {
        /// Image name (e.g., alpine:3.18)
        image: String,

        /// Scan for vulnerabilities
        #[arg(long)]
        vuln: bool,

        /// Scan for misconfigurations
        #[arg(long)]
        misconfig: bool,

        /// Scan for secrets
        #[arg(long)]
        secret: bool,

        /// Scan for licenses
        #[arg(long)]
        license: bool,
    },
    /// Scan filesystem
    Fs {
        /// Path to scan
        path: String,

        /// Scan for vulnerabilities
        #[arg(long)]
        vuln: bool,

        /// Scan for misconfigurations
        #[arg(long)]
        misconfig: bool,

        /// Scan for secrets
        #[arg(long)]
        secret: bool,

        /// Scan for licenses
        #[arg(long)]
        license: bool,
    },
    /// Scan Git repository
    Repo {
        /// Repository URL
        url: String,

        /// Scan for vulnerabilities
        #[arg(long)]
        vuln: bool,

        /// Scan for misconfigurations
        #[arg(long)]
        misconfig: bool,

        /// Scan for secrets
        #[arg(long)]
        secret: bool,

        /// Scan for licenses
        #[arg(long)]
        license: bool,
    },
    /// Scan Kubernetes manifests
    K8s {
        /// Path to Kubernetes manifests
        path: String,

        /// Scan for vulnerabilities
        #[arg(long)]
        vuln: bool,

        /// Scan for misconfigurations
        #[arg(long)]
        misconfig: bool,

        /// Scan for secrets
        #[arg(long)]
        secret: bool,

        /// Scan for licenses
        #[arg(long)]
        license: bool,
    },
    /// Generate SBOM
    Sbom {
        /// Target to analyze
        target: String,

        /// SBOM format (cyclonedx, spdx)
        #[arg(short, long, default_value = "cyclonedx")]
        format: String,

        /// Output file
        #[arg(short, long)]
        output: String,
    },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.debug {
        std::env::set_var("RUST_LOG", "debug");
    }

    deepsys::init().await?;

    match cli.command {
        Commands::Image { image, vuln, misconfig, secret, license } => {
            info!("Scanning image: {}", image);
            let target = deepsys::ScanTarget::Image { name: image };
            let result = deepsys::scan(target).await?;

            println!("Scan completed for image: {}", image);
            println!("Found {} issues", result.issues().len());
        }
        Commands::Fs { path, vuln, misconfig, secret, license } => {
            info!("Scanning filesystem: {}", path);
            let target = deepsys::ScanTarget::Filesystem { path };
            let result = deepsys::scan(target).await?;

            println!("Scan completed for path: {}", path);
            println!("Found {} issues", result.issues().len());
        }
        Commands::Repo { url, vuln, misconfig, secret, license } => {
            info!("Scanning repository: {}", url);
            let target = deepsys::ScanTarget::Repository { url };
            let result = deepsys::scan(target).await?;

            println!("Scan completed for repository: {}", url);
            println!("Found {} issues", result.issues().len());
        }
        Commands::K8s { path, vuln, misconfig, secret, license } => {
            info!("Scanning Kubernetes manifests: {}", path);
            let target = deepsys::ScanTarget::Kubernetes { path };
            let result = deepsys::scan(target).await?;

            println!("Scan completed for Kubernetes: {}", path);
            println!("Found {} issues", result.issues().len());
        }
        Commands::Sbom { target, format, output } => {
            info!("Generating SBOM for: {} (format: {})", target, format);
            println!("SBOM generation not yet implemented");
        }
    }

    Ok(())
}
