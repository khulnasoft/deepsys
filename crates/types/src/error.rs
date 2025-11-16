//! # Error Types
//!
//! Error types and utilities converted from Go pkg/types/error.go

use thiserror::Error;

/// Errors that can occur during type operations
#[derive(Error, Debug)]
pub enum TypeError {
    #[error("Invalid severity level: {0}")]
    InvalidSeverity(String),

    #[error("Invalid scan target: {0}")]
    InvalidScanTarget(String),

    #[error("Invalid vulnerability ID: {0}")]
    InvalidVulnerabilityId(String),

    #[error("Invalid finding type: {0}")]
    InvalidFindingType(String),

    #[error("Invalid artifact type: {0}")]
    InvalidArtifactType(String),

    #[error("Invalid package type: {0}")]
    InvalidPackageType(String),

    #[error("Invalid scanner type: {0}")]
    InvalidScannerType(String),

    #[error("Invalid result class: {0}")]
    InvalidResultClass(String),

    #[error("Invalid compliance: {0}")]
    InvalidCompliance(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("YAML serialization error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("UUID error: {0}")]
    UuidError(#[from] uuid::Error),
}

/// Result type for type operations
pub type Result<T> = std::result::Result<T, TypeError>;

/// Utility functions for error handling
pub mod error_utils {
    use super::*;

    /// Convert string to severity with error handling
    pub fn parse_severity(s: &str) -> Result<crate::Severity> {
        crate::Severity::from_str(s).map_err(|_| TypeError::InvalidSeverity(s.to_string()))
    }

    /// Convert string to scanner with error handling
    pub fn parse_scanner(s: &str) -> Result<crate::Scanner> {
        // This would need to be implemented based on the scanner enum
        // For now, return a placeholder
        Err(TypeError::InvalidScannerType(s.to_string()))
    }

    /// Convert string to finding type with error handling
    pub fn parse_finding_type(s: &str) -> Result<crate::finding::FindingType> {
        match s {
            crate::finding::FINDING_TYPE_VULNERABILITY => Ok(crate::finding::FindingType::Vulnerability),
            crate::finding::FINDING_TYPE_MISCONFIGURATION => Ok(crate::finding::FindingType::Misconfiguration),
            crate::finding::FINDING_TYPE_SECRET => Ok(crate::finding::FindingType::Secret),
            crate::finding::FINDING_TYPE_LICENSE => Ok(crate::finding::FindingType::License),
            _ => Err(TypeError::InvalidFindingType(s.to_string())),
        }
    }

    /// Convert string to artifact type with error handling
    pub fn parse_artifact_type(s: &str) -> Result<crate::ArtifactType> {
        // This would need to be implemented based on the artifact type enum
        Err(TypeError::InvalidArtifactType(s.to_string()))
    }

    /// Convert string to result class with error handling
    pub fn parse_result_class(s: &str) -> Result<crate::ResultClass> {
        match s {
            crate::CLASS_UNKNOWN => Ok(crate::ResultClass::Unknown),
            crate::CLASS_OS_PKG => Ok(crate::ResultClass::OsPkg),
            crate::CLASS_LANG_PKG => Ok(crate::ResultClass::LangPkg),
            crate::CLASS_CONFIG => Ok(crate::ResultClass::Config),
            crate::CLASS_SECRET => Ok(crate::ResultClass::Secret),
            crate::CLASS_LICENSE => Ok(crate::ResultClass::License),
            crate::CLASS_LICENSE_FILE => Ok(crate::ResultClass::LicenseFile),
            crate::CLASS_CUSTOM => Ok(crate::ResultClass::Custom),
            _ => Err(TypeError::InvalidResultClass(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = TypeError::InvalidSeverity("invalid".to_string());
        assert_eq!(error.to_string(), "Invalid severity level: invalid");

        let error = TypeError::InvalidFindingType("invalid".to_string());
        assert_eq!(error.to_string(), "Invalid finding type: invalid");
    }

    #[test]
    fn test_parse_severity() {
        assert!(error_utils::parse_severity("CRITICAL").is_ok());
        assert!(error_utils::parse_severity("invalid").is_err());
    }

    #[test]
    fn test_parse_finding_type() {
        assert_eq!(error_utils::parse_finding_type("vulnerability").unwrap(),
                   crate::finding::FindingType::Vulnerability);
        assert!(error_utils::parse_finding_type("invalid").is_err());
    }

    #[test]
    fn test_parse_result_class() {
        assert_eq!(error_utils::parse_result_class("os-pkgs").unwrap(),
                   crate::ResultClass::OsPkg);
        assert_eq!(error_utils::parse_result_class("config").unwrap(),
                   crate::ResultClass::Config);
        assert!(error_utils::parse_result_class("invalid").is_err());
    }
}
