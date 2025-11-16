//! # Scan Types
//!
//! Core scanning types and configurations converted from Go pkg/types/scan.go

use serde::{Deserialize, Serialize};
use std::fmt;

/// Scanner type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scanner {
    Unknown,
    None,
    SBOM,
    Vulnerability,
    Misconfiguration,
    Secret,
    RBAC,
    License,
}

impl fmt::Display for Scanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scanner::Unknown => write!(f, "unknown"),
            Scanner::None => write!(f, "none"),
            Scanner::SBOM => write!(f, "sbom"),
            Scanner::Vulnerability => write!(f, "vuln"),
            Scanner::Misconfiguration => write!(f, "misconfig"),
            Scanner::Secret => write!(f, "secret"),
            Scanner::RBAC => write!(f, "rbac"),
            Scanner::License => write!(f, "license"),
        }
    }
}

impl From<String> for Scanner {
    fn from(s: String) -> Self {
        match s.as_str() {
            "none" => Scanner::None,
            "sbom" => Scanner::SBOM,
            "vuln" => Scanner::Vulnerability,
            "misconfig" => Scanner::Misconfiguration,
            "secret" => Scanner::Secret,
            "rbac" => Scanner::RBAC,
            "license" => Scanner::License,
            _ => Scanner::Unknown,
        }
    }
}

/// Collection of scanners
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scanners {
    pub scanners: Vec<Scanner>,
}

impl Default for Scanners {
    fn default() -> Self {
        Self {
            scanners: vec![Scanner::Vulnerability, Scanner::Misconfiguration, Scanner::RBAC, Scanner::Secret, Scanner::License, Scanner::None],
        }
    }
}

impl Scanners {
    /// Enable a scanner
    pub fn enable(&mut self, scanner: Scanner) {
        if !self.enabled(scanner) {
            self.scanners.push(scanner);
        }
    }

    /// Check if scanner is enabled
    pub fn enabled(&self, scanner: Scanner) -> bool {
        self.scanners.contains(&scanner)
    }

    /// Check if any of the specified scanners are enabled
    pub fn any_enabled(&self, scanners: &[Scanner]) -> bool {
        scanners.iter().any(|s| self.enabled(*s))
    }

    /// Get all enabled scanners
    pub fn all_enabled(&self) -> &[Scanner] {
        &self.scanners
    }
}

/// Scanner constants
pub const SCANNER_UNKNOWN: &str = "unknown";
pub const SCANNER_NONE: &str = "none";
pub const SCANNER_SBOM: &str = "sbom";
pub const SCANNER_VULNERABILITY: &str = "vuln";
pub const SCANNER_MISCONFIGURATION: &str = "misconfig";
pub const SCANNER_SECRET: &str = "secret";
pub const SCANNER_RBAC: &str = "rbac";
pub const SCANNER_LICENSE: &str = "license";

/// All available scanners
pub const ALL_SCANNERS: &[Scanner] = &[
    Scanner::Vulnerability,
    Scanner::Misconfiguration,
    Scanner::RBAC,
    Scanner::Secret,
    Scanner::License,
    Scanner::None,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_display() {
        assert_eq!(format!("{}", Scanner::Vulnerability), "vuln");
        assert_eq!(format!("{}", Scanner::Misconfiguration), "misconfig");
        assert_eq!(format!("{}", Scanner::Secret), "secret");
        assert_eq!(format!("{}", Scanner::License), "license");
    }

    #[test]
    fn test_scanners_operations() {
        let mut scanners = Scanners::default();

        assert!(scanners.enabled(Scanner::Vulnerability));
        assert!(scanners.enabled(Scanner::Secret));

        scanners.enable(Scanner::RBAC);
        assert!(scanners.enabled(Scanner::RBAC));

        assert!(scanners.any_enabled(&[Scanner::Vulnerability, Scanner::Misconfiguration]));
        assert!(!scanners.any_enabled(&[Scanner::SBOM]));
    }
}
