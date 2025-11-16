//! # Finding Types
//!
//! Security finding types and interfaces converted from Go pkg/types/finding.go

use serde::{Deserialize, Serialize};
use std::fmt;

/// Type of security finding
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingType {
    Vulnerability,
    Misconfiguration,
    Secret,
    License,
}

impl fmt::Display for FindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingType::Vulnerability => write!(f, "vulnerability"),
            FindingType::Misconfiguration => write!(f, "misconfiguration"),
            FindingType::Secret => write!(f, "secret"),
            FindingType::License => write!(f, "license"),
        }
    }
}

impl From<String> for FindingType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "vulnerability" => FindingType::Vulnerability,
            "misconfiguration" => FindingType::Misconfiguration,
            "secret" => FindingType::Secret,
            "license" => FindingType::License,
            _ => FindingType::Vulnerability, // Default fallback
        }
    }
}

/// Status of a finding (from VEX or other sources)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingStatus {
    /// Finding is ignored (e.g., from .deepsysignore)
    Ignored,
    /// Finding status is unknown
    Unknown,
    /// Finding is not affected (from VEX)
    NotAffected,
    /// Finding is affected (from VEX)
    Affected,
    /// Finding is fixed (from VEX)
    Fixed,
    /// Finding is under investigation (from VEX)
    UnderInvestigation,
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingStatus::Ignored => write!(f, "ignored"),
            FindingStatus::Unknown => write!(f, "unknown"),
            FindingStatus::NotAffected => write!(f, "not_affected"),
            FindingStatus::Affected => write!(f, "affected"),
            FindingStatus::Fixed => write!(f, "fixed"),
            FindingStatus::UnderInvestigation => write!(f, "under_investigation"),
        }
    }
}

impl From<String> for FindingStatus {
    fn from(s: String) -> Self {
        match s.as_str() {
            "ignored" => FindingStatus::Ignored,
            "unknown" => FindingStatus::Unknown,
            "not_affected" => FindingStatus::NotAffected,
            "affected" => FindingStatus::Affected,
            "fixed" => FindingStatus::Fixed,
            "under_investigation" => FindingStatus::UnderInvestigation,
            _ => FindingStatus::Unknown,
        }
    }
}

/// Trait for all security findings
pub trait Finding: Send + Sync {
    /// Get the type of this finding
    fn finding_type(&self) -> FindingType;

    /// Get the title/description of this finding
    fn title(&self) -> &str;

    /// Get the severity of this finding
    fn severity(&self) -> crate::Severity {
        crate::Severity::Unknown
    }

    /// Get the file path where this finding was detected
    fn file_path(&self) -> Option<&str> {
        None
    }

    /// Get the line number where this finding was detected
    fn line_number(&self) -> Option<usize> {
        None
    }
}

/// Modified finding represents a security finding that has been modified by an external source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifiedFinding {
    /// Type of finding
    pub finding_type: FindingType,

    /// Status of the finding
    pub status: FindingStatus,

    /// Statement explaining the modification
    pub statement: String,

    /// Source of the modification (e.g., VEX, .deepsysignore)
    pub source: String,

    /// The original finding
    pub finding: SecurityFinding,
}

/// Security finding enum that can hold any type of security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecurityFinding {
    Vulnerability(crate::Vulnerability),
    Misconfiguration(crate::Misconfiguration),
    Secret(crate::Secret),
    License(crate::LicenseIssue),
}

impl Finding for SecurityFinding {
    fn finding_type(&self) -> FindingType {
        match self {
            SecurityFinding::Vulnerability(_) => FindingType::Vulnerability,
            SecurityFinding::Misconfiguration(_) => FindingType::Misconfiguration,
            SecurityFinding::Secret(_) => FindingType::Secret,
            SecurityFinding::License(_) => FindingType::License,
        }
    }

    fn title(&self) -> &str {
        match self {
            SecurityFinding::Vulnerability(v) => &v.title,
            SecurityFinding::Misconfiguration(m) => &m.title,
            SecurityFinding::Secret(s) => &s.title,
            SecurityFinding::License(l) => &l.license_name,
        }
    }

    fn severity(&self) -> crate::Severity {
        match self {
            SecurityFinding::Vulnerability(v) => v.severity.clone(),
            SecurityFinding::Misconfiguration(m) => m.severity.clone(),
            SecurityFinding::Secret(s) => s.severity.clone(),
            SecurityFinding::License(_) => crate::Severity::Info,
        }
    }

    fn file_path(&self) -> Option<&str> {
        match self {
            SecurityFinding::Vulnerability(v) => v.file_path.as_deref(),
            SecurityFinding::Misconfiguration(m) => Some(&m.file_path),
            SecurityFinding::Secret(s) => Some(&s.file_path),
            SecurityFinding::License(_) => None,
        }
    }

    fn line_number(&self) -> Option<usize> {
        match self {
            SecurityFinding::Vulnerability(v) => v.line_number,
            SecurityFinding::Misconfiguration(m) => m.line_range.map(|(start, _)| start),
            SecurityFinding::Secret(s) => Some(s.start_line),
            SecurityFinding::License(_) => None,
        }
    }
}

/// Create a new modified finding
pub fn new_modified_finding(
    finding: SecurityFinding,
    status: FindingStatus,
    statement: String,
    source: String,
) -> ModifiedFinding {
    ModifiedFinding {
        finding_type: finding.finding_type(),
        status,
        statement,
        source,
        finding,
    }
}

/// Finding type constants
pub const FINDING_TYPE_VULNERABILITY: &str = "vulnerability";
pub const FINDING_TYPE_MISCONFIGURATION: &str = "misconfiguration";
pub const FINDING_TYPE_SECRET: &str = "secret";
pub const FINDING_TYPE_LICENSE: &str = "license";

/// Finding status constants
pub const FINDING_STATUS_IGNORED: &str = "ignored";
pub const FINDING_STATUS_UNKNOWN: &str = "unknown";
pub const FINDING_STATUS_NOT_AFFECTED: &str = "not_affected";
pub const FINDING_STATUS_AFFECTED: &str = "affected";
pub const FINDING_STATUS_FIXED: &str = "fixed";
pub const FINDING_STATUS_UNDER_INVESTIGATION: &str = "under_investigation";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Severity, Vulnerability};

    #[test]
    fn test_finding_type_display() {
        assert_eq!(format!("{}", FindingType::Vulnerability), "vulnerability");
        assert_eq!(format!("{}", FindingType::Misconfiguration), "misconfiguration");
        assert_eq!(format!("{}", FindingType::Secret), "secret");
        assert_eq!(format!("{}", FindingType::License), "license");
    }

    #[test]
    fn test_finding_status_display() {
        assert_eq!(format!("{}", FindingStatus::Ignored), "ignored");
        assert_eq!(format!("{}", FindingStatus::NotAffected), "not_affected");
        assert_eq!(format!("{}", FindingStatus::Fixed), "fixed");
        assert_eq!(format!("{}", FindingStatus::UnderInvestigation), "under_investigation");
    }

    #[test]
    fn test_security_finding_implementation() {
        let vuln = Vulnerability {
            id: "CVE-2023-1234".to_string(),
            package_name: "test".to_string(),
            package_version: "1.0.0".to_string(),
            severity: Severity::High,
            title: "Test vulnerability".to_string(),
            description: "Test description".to_string(),
            cvss_score: Some(7.5),
            cvss_vector: None,
            references: vec![],
            fixed_version: None,
            published_date: None,
            last_modified_date: None,
            data_source: None,
            file_path: Some("test.txt".to_string()),
            line_number: Some(10),
            custom_fields: std::collections::HashMap::new(),
        };

        let finding = SecurityFinding::Vulnerability(vuln);

        assert_eq!(finding.finding_type(), FindingType::Vulnerability);
        assert_eq!(finding.title(), "Test vulnerability");
        assert_eq!(finding.severity(), Severity::High);
        assert_eq!(finding.file_path(), Some("test.txt"));
        assert_eq!(finding.line_number(), Some(10));
    }

    #[test]
    fn test_modified_finding_creation() {
        let vuln = Vulnerability {
            id: "CVE-2023-1234".to_string(),
            package_name: "test".to_string(),
            package_version: "1.0.0".to_string(),
            severity: Severity::High,
            title: "Test vulnerability".to_string(),
            description: "Test description".to_string(),
            cvss_score: Some(7.5),
            cvss_vector: None,
            references: vec![],
            fixed_version: None,
            published_date: None,
            last_modified_date: None,
            data_source: None,
            file_path: None,
            line_number: None,
            custom_fields: std::collections::HashMap::new(),
        };

        let finding = SecurityFinding::Vulnerability(vuln);
        let modified = new_modified_finding(
            finding,
            FindingStatus::NotAffected,
            "Not applicable to our environment".to_string(),
            "VEX".to_string(),
        );

        assert_eq!(modified.finding_type, FindingType::Vulnerability);
        assert_eq!(modified.status, FindingStatus::NotAffected);
        assert_eq!(modified.source, "VEX");
    }
}
