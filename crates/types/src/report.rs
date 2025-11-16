//! # Report Types
//!
//! Scan report and result types converted from Go pkg/types/report.go

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Scan report containing all results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Schema version
    pub schema_version: i32,

    /// Unique report ID
    pub report_id: String,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Artifact ID (e.g., image config hash)
    pub artifact_id: String,

    /// Artifact name
    pub artifact_name: String,

    /// Artifact type
    pub artifact_type: crate::ArtifactType,

    /// Metadata about the artifact
    pub metadata: Metadata,

    /// Scan results
    pub results: Results,

    /// Parsed SBOM (internal use only)
    #[serde(skip)]
    pub bom: Option<String>,
}

/// Artifact metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Size in bytes
    pub size: i64,

    /// Operating system information
    pub os: Option<crate::OS>,

    // Container image metadata
    pub image_id: String,
    pub diff_ids: Vec<String>,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    pub image_config: crate::ImageConfig,
    pub layers: crate::Layers,

    // Git repository metadata
    pub repo_url: String,
    pub branch: String,
    pub tags: Vec<String>,
    pub commit: String,
    pub commit_msg: String,
    pub author: String,
    pub committer: String,
}

/// Collection of scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Results(pub Vec<Result>);

impl std::ops::Deref for Results {
    type Target = Vec<Result>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Results {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Individual scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    /// Target information
    pub target: String,

    /// Class of results
    pub class: ResultClass,

    /// Result type
    pub r#type: String,

    /// Vulnerabilities found
    pub vulnerabilities: Vec<crate::Vulnerability>,

    /// Misconfigurations found
    pub misconfigurations: Vec<crate::Misconfiguration>,

    /// Secrets found
    pub secrets: Vec<crate::Secret>,

    /// License issues found
    pub licenses: Vec<crate::LicenseIssue>,

    /// Packages found
    pub packages: crate::Packages,

    /// Custom resources
    pub custom_resources: Vec<crate::CustomResource>,
}

/// Result classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResultClass {
    Unknown,
    OsPkg,
    LangPkg,
    Config,
    Secret,
    License,
    LicenseFile,
    Custom,
}

impl std::fmt::Display for ResultClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultClass::Unknown => write!(f, "unknown"),
            ResultClass::OsPkg => write!(f, "os-pkgs"),
            ResultClass::LangPkg => write!(f, "lang-pkgs"),
            ResultClass::Config => write!(f, "config"),
            ResultClass::Secret => write!(f, "secret"),
            ResultClass::License => write!(f, "license"),
            ResultClass::LicenseFile => write!(f, "license-file"),
            ResultClass::Custom => write!(f, "custom"),
        }
    }
}

impl From<String> for ResultClass {
    fn from(s: String) -> Self {
        match s.as_str() {
            "os-pkgs" => ResultClass::OsPkg,
            "lang-pkgs" => ResultClass::LangPkg,
            "config" => ResultClass::Config,
            "secret" => ResultClass::Secret,
            "license" => ResultClass::License,
            "license-file" => ResultClass::LicenseFile,
            "custom" => ResultClass::Custom,
            _ => ResultClass::Unknown,
        }
    }
}

/// Compliance type
pub type Compliance = String;

/// Output format
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Format {
    Table,
    Json,
    Template,
    Sarif,
    CycloneDX,
    SPDX,
    SPDXJSON,
    GitHub,
    CosignVuln,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Format::Table => write!(f, "table"),
            Format::Json => write!(f, "json"),
            Format::Template => write!(f, "template"),
            Format::Sarif => write!(f, "sarif"),
            Format::CycloneDX => write!(f, "cyclonedx"),
            Format::SPDX => write!(f, "spdx"),
            Format::SPDXJSON => write!(f, "spdx-json"),
            Format::GitHub => write!(f, "github"),
            Format::CosignVuln => write!(f, "cosign-vuln"),
        }
    }
}

/// Compliance constants
pub const COMPLIANCE_K8S_NSA10: &str = "k8s-nsa-1.0";
pub const COMPLIANCE_K8S_CIS123: &str = "k8s-cis-1.23";
pub const COMPLIANCE_K8S_PSS_BASELINE01: &str = "k8s-pss-baseline-0.1";
pub const COMPLIANCE_K8S_PSS_RESTRICTED01: &str = "k8s-pss-restricted-0.1";
pub const COMPLIANCE_AWS_CIS12: &str = "aws-cis-1.2";
pub const COMPLIANCE_AWS_CIS14: &str = "aws-cis-1.4";
pub const COMPLIANCE_DOCKER_CIS160: &str = "docker-cis-1.6.0";
pub const COMPLIANCE_EKS_CIS14: &str = "eks-cis-1.4";
pub const COMPLIANCE_RKE2_CIS124: &str = "rke2-cis-1.24";

/// Built-in Kubernetes compliance frameworks
pub const BUILT_IN_K8S_COMPLIANCES: &[&str] = &[
    COMPLIANCE_K8S_NSA10,
    COMPLIANCE_K8S_CIS123,
    COMPLIANCE_EKS_CIS14,
    COMPLIANCE_RKE2_CIS124,
    COMPLIANCE_K8S_PSS_BASELINE01,
    COMPLIANCE_K8S_PSS_RESTRICTED01,
];

/// Supported output formats
pub const SUPPORTED_FORMATS: &[Format] = &[
    Format::Table,
    Format::Json,
    Format::Template,
    Format::Sarif,
    Format::CycloneDX,
    Format::SPDX,
    Format::SPDXJSON,
    Format::GitHub,
    Format::CosignVuln,
];

/// Format constants
pub const FORMAT_TABLE: &str = "table";
pub const FORMAT_JSON: &str = "json";
pub const FORMAT_TEMPLATE: &str = "template";
pub const FORMAT_SARIF: &str = "sarif";
pub const FORMAT_CYCLONEDX: &str = "cyclonedx";
pub const FORMAT_SPDX: &str = "spdx";
pub const FORMAT_SPDX_JSON: &str = "spdx-json";
pub const FORMAT_GITHUB: &str = "github";
pub const FORMAT_COSIGN_VULN: &str = "cosign-vuln";

/// Result class constants
pub const CLASS_UNKNOWN: &str = "unknown";
pub const CLASS_OS_PKG: &str = "os-pkgs";
pub const CLASS_LANG_PKG: &str = "lang-pkgs";
pub const CLASS_CONFIG: &str = "config";
pub const CLASS_SECRET: &str = "secret";
pub const CLASS_LICENSE: &str = "license";
pub const CLASS_LICENSE_FILE: &str = "license-file";
pub const CLASS_CUSTOM: &str = "custom";

impl Report {
    /// Create a new scan report
    pub fn new(artifact_name: String, artifact_type: crate::ArtifactType) -> Self {
        Self {
            schema_version: 1,
            report_id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            artifact_id: Uuid::new_v4().to_string(),
            artifact_name,
            artifact_type,
            metadata: Metadata::default(),
            results: Results(Vec::new()),
            bom: None,
        }
    }

    /// Add a result to the report
    pub fn add_result(&mut self, result: Result) {
        self.results.0.push(result);
    }

    /// Get all vulnerabilities from the report
    pub fn vulnerabilities(&self) -> Vec<&crate::Vulnerability> {
        self.results.iter().flat_map(|r| &r.vulnerabilities).collect()
    }

    /// Get all misconfigurations from the report
    pub fn misconfigurations(&self) -> Vec<&crate::Misconfiguration> {
        self.results.iter().flat_map(|r| &r.misconfigurations).collect()
    }

    /// Get all secrets from the report
    pub fn secrets(&self) -> Vec<&crate::Secret> {
        self.results.iter().flat_map(|r| &r.secrets).collect()
    }

    /// Get all license issues from the report
    pub fn licenses(&self) -> Vec<&crate::LicenseIssue> {
        self.results.iter().flat_map(|r| &r.licenses).collect()
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            size: 0,
            os: None,
            image_id: String::new(),
            diff_ids: Vec::new(),
            repo_tags: Vec::new(),
            repo_digests: Vec::new(),
            image_config: crate::ImageConfig::default(),
            layers: crate::Layers::default(),
            repo_url: String::new(),
            branch: String::new(),
            tags: Vec::new(),
            commit: String::new(),
            commit_msg: String::new(),
            author: String::new(),
            committer: String::new(),
        }
    }
}

impl Result {
    /// Create a new result
    pub fn new(target: String, class: ResultClass, r#type: String) -> Self {
        Self {
            target,
            class,
            r#type,
            vulnerabilities: Vec::new(),
            misconfigurations: Vec::new(),
            secrets: Vec::new(),
            licenses: Vec::new(),
            packages: crate::Packages::default(),
            custom_resources: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Severity, ArtifactType};

    #[test]
    fn test_report_creation() {
        let mut report = Report::new("nginx:latest".to_string(), ArtifactType::ContainerImage);

        assert_eq!(report.schema_version, 1);
        assert!(!report.report_id.is_empty());
        assert_eq!(report.artifact_name, "nginx:latest");
        assert_eq!(report.artifact_type, ArtifactType::ContainerImage);
    }

    #[test]
    fn test_result_class_display() {
        assert_eq!(format!("{}", ResultClass::OsPkg), "os-pkgs");
        assert_eq!(format!("{}", ResultClass::LangPkg), "lang-pkgs");
        assert_eq!(format!("{}", ResultClass::Config), "config");
        assert_eq!(format!("{}", ResultClass::Secret), "secret");
        assert_eq!(format!("{}", ResultClass::License), "license");
        assert_eq!(format!("{}", ResultClass::LicenseFile), "license-file");
        assert_eq!(format!("{}", ResultClass::Custom), "custom");
        assert_eq!(format!("{}", ResultClass::Unknown), "unknown");
    }

    #[test]
    fn test_format_display() {
        assert_eq!(format!("{}", Format::Table), "table");
        assert_eq!(format!("{}", Format::Json), "json");
        assert_eq!(format!("{}", Format::Sarif), "sarif");
        assert_eq!(format!("{}", Format::CycloneDX), "cyclonedx");
        assert_eq!(format!("{}", Format::SPDX), "spdx");
    }

    #[test]
    fn test_report_operations() {
        let mut report = Report::new("test".to_string(), ArtifactType::ContainerImage);

        let result = Result::new("test".to_string(), ResultClass::Config, "kubernetes".to_string());
        report.add_result(result);

        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].class, ResultClass::Config);
    }
}
