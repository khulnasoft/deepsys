//! # Deepsys - Deep Security Scanner
//!
//! A comprehensive security scanner written in Rust, providing vulnerability scanning,
//! misconfiguration detection, secret scanning, and license compliance checking
//! for containers, filesystems, Git repositories, and Kubernetes environments.
//!
//! Deepsys is a Rust reimplementation of Deepsys, leveraging Rust's memory safety,
//! performance, and rich type system to provide enhanced security guarantees.

pub mod cli;
pub mod core;
pub mod scanner;
pub mod utils;

// Re-export commonly used types from the types crate
pub use deepsys_types::{ScanResult, ScanTarget, Vulnerability, Misconfiguration, Secret, SecurityIssue, Severity};
pub use core::{Scanner, ScannerBuilder};
pub use scanner::{ImageScanner, FilesystemScanner, GitScanner, KubernetesScanner};

use anyhow::Result;
use tracing::{info, warn};

/// Initialize the deepsys scanner with default configuration
pub async fn init() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Deepsys security scanner initialized");
    Ok(())
}

/// Run a security scan on the specified target
pub async fn scan(target: ScanTarget) -> Result<ScanResult> {
    info!("Starting security scan for target: {:?}", target);

    let scanner = ScannerBuilder::new()
        .with_vulnerability_scanning(true)
        .with_misconfiguration_scanning(true)
        .with_secret_scanning(true)
        .with_license_scanning(true)
        .build();

    let result = scanner.scan(target).await?;

    info!("Security scan completed. Found {} issues", result.issues().len());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initialization() {
        init().await.expect("Failed to initialize deepsys");
    }
}
