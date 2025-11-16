//! # Misconfiguration Types
//!
//! Misconfiguration detection types converted from Go pkg/types/misconfiguration.go

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::finding::Finding;

/// Misconfiguration status
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MisconfStatus {
    /// Configuration passed validation
    Passed,
    /// Configuration failed validation
    Failure,
    /// Configuration raised an exception
    Exception,
}

impl std::fmt::Display for MisconfStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MisconfStatus::Passed => write!(f, "PASS"),
            MisconfStatus::Failure => write!(f, "FAIL"),
            MisconfStatus::Exception => write!(f, "EXCEPTION"),
        }
    }
}

impl From<String> for MisconfStatus {
    fn from(s: String) -> Self {
        match s.to_uppercase().as_str() {
            "PASS" => MisconfStatus::Passed,
            "FAIL" => MisconfStatus::Failure,
            "EXCEPTION" => MisconfStatus::Exception,
            _ => MisconfStatus::Failure, // Default to failure for unknown
        }
    }
}

/// Detected misconfiguration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedMisconfiguration {
    /// Misconfiguration type
    pub r#type: String,

    /// Misconfiguration ID
    pub id: String,

    /// Deprecated: Use ID field instead
    pub avd_id: String,

    /// Title of the misconfiguration
    pub title: String,

    /// Description of the issue
    pub description: String,

    /// Message with details
    pub message: String,

    /// Namespace for organization
    pub namespace: String,

    /// Query that detected this issue
    pub query: String,

    /// Resolution steps
    pub resolution: String,

    /// Severity level
    pub severity: crate::Severity,

    /// Primary URL for reference
    pub primary_url: String,

    /// Reference URLs
    pub references: Vec<String>,

    /// Status of this misconfiguration
    pub status: MisconfStatus,

    /// Layer where this was detected (for containers)
    pub layer: crate::Layer,

    /// Metadata about the cause
    pub cause_metadata: crate::CauseMetadata,

    /// Debug traces
    pub traces: Vec<String>,

    /// Custom fields
    pub custom_fields: HashMap<String, String>,
}

impl Finding for DetectedMisconfiguration {
    fn finding_type(&self) -> crate::finding::FindingType {
        crate::finding::FindingType::Misconfiguration
    }

    fn title(&self) -> &str {
        &self.title
    }

    fn severity(&self) -> crate::Severity {
        self.severity.clone()
    }
}

/// Misconfiguration status constants
pub const MISCONF_STATUS_PASSED: &str = "PASS";
pub const MISCONF_STATUS_FAILURE: &str = "FAIL";
pub const MISCONF_STATUS_EXCEPTION: &str = "EXCEPTION";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Severity, finding::Finding};

    #[test]
    fn test_misconf_status_display() {
        assert_eq!(format!("{}", MisconfStatus::Passed), "PASS");
        assert_eq!(format!("{}", MisconfStatus::Failure), "FAIL");
        assert_eq!(format!("{}", MisconfStatus::Exception), "EXCEPTION");
    }

    #[test]
    fn test_detected_misconfiguration_implementation() {
        let misconf = DetectedMisconfiguration {
            r#type: "kubernetes".to_string(),
            id: "KSV001".to_string(),
            avd_id: "AVD-KSV-0001".to_string(),
            title: "Root filesystem is not read-only".to_string(),
            description: "Container has writable root filesystem".to_string(),
            message: "spec.containers[0].securityContext.readOnlyRootFilesystem is not set".to_string(),
            namespace: "builtin.kubernetes.KSV001".to_string(),
            query: "spec.containers[*].securityContext.readOnlyRootFilesystem == false".to_string(),
            resolution: "Set readOnlyRootFilesystem: true".to_string(),
            severity: crate::Severity::Medium,
            primary_url: "https://kubernetes.io/docs/concepts/policy/pod-security-policy/".to_string(),
            references: vec!["https://kubernetes.io/docs/concepts/policy/pod-security-policy/".to_string()],
            status: MisconfStatus::Failure,
            layer: crate::Layer {
                digest: "sha256:123".to_string(),
                diff_id: "sha256:456".to_string(),
                created_by: Some("RUN apt-get update".to_string()),
            },
            cause_metadata: crate::CauseMetadata {
                resource: "Pod".to_string(),
                provider: "Kubernetes".to_string(),
                service: "k8s".to_string(),
                start_line: 10,
                end_line: 15,
            },
            traces: vec!["trace1".to_string(), "trace2".to_string()],
            custom_fields: HashMap::new(),
        };

        assert_eq!(misconf.finding_type(), crate::finding::FindingType::Misconfiguration);
        assert_eq!(misconf.title(), "Root filesystem is not read-only");
        assert_eq!(misconf.severity(), crate::Severity::Medium);
    }

    #[test]
    fn test_misconf_status_from_string() {
        assert_eq!(MisconfStatus::from("PASS".to_string()), MisconfStatus::Passed);
        assert_eq!(MisconfStatus::from("FAIL".to_string()), MisconfStatus::Failure);
        assert_eq!(MisconfStatus::from("EXCEPTION".to_string()), MisconfStatus::Exception);
        assert_eq!(MisconfStatus::from("invalid".to_string()), MisconfStatus::Failure);
    }
}
