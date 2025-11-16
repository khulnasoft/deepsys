//! # Deepsys Types
//!
//! Core type definitions for the Deepsys security scanner. This crate provides
//! all the fundamental data structures used throughout the scanner, with strong
//! typing and memory safety guarantees.
//!
//! Converted from Deepsys Go types (pkg/types) with idiomatic Rust patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use thiserror::Error;

pub mod scan;
pub mod finding;
pub mod vulnerability;
pub mod misconfiguration;
pub mod secret;
pub mod license;
pub mod report;
pub mod error;

/// Re-export all modules for convenience
pub use scan::*;
pub use finding::*;
pub use vulnerability::*;
pub use misconfiguration::*;
pub use secret::*;
pub use license::*;
pub use report::*;
pub use error::*;

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
}

/// Result type for type operations
pub type Result<T> = std::result::Result<T, TypeError>;

/// Operating system information
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OS {
    /// Family (e.g., "debian", "alpine", "redhat")
    pub family: String,
    /// Name (e.g., "ubuntu", "alpine", "centos")
    pub name: String,
    /// Version (e.g., "20.04", "3.18")
    pub version: Option<String>,
    /// Extended version information
    pub extended_version: Option<String>,
}

impl OS {
    /// Create a new OS instance
    pub fn new(family: String, name: String) -> Self {
        Self {
            family,
            name,
            version: None,
            extended_version: None,
        }
    }

    /// Create OS from string format (e.g., "debian:ubuntu:20.04")
    pub fn from_string(s: &str) -> Self {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.len() {
            1 => Self::new(parts[0].to_string(), parts[0].to_string()),
            2 => Self::new(parts[0].to_string(), parts[1].to_string()),
            3 => Self {
                family: parts[0].to_string(),
                name: parts[1].to_string(),
                version: Some(parts[2].to_string()),
                extended_version: None,
            },
            _ => Self::new(s.to_string(), s.to_string()),
        }
    }
}

impl std::fmt::Display for OS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.family, self.name)?;
        if let Some(ref version) = self.version {
            write!(f, ":{}", version)?;
        }
        Ok(())
    }
}

/// Repository information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    /// Repository URL
    pub url: String,
    /// Branch name
    pub branch: Option<String>,
    /// Commit hash
    pub commit: Option<String>,
    /// Tag
    pub tag: Option<String>,
}

impl Repository {
    /// Create a new repository instance
    pub fn new(url: String) -> Self {
        Self {
            url,
            branch: None,
            commit: None,
            tag: None,
        }
    }
}

/// Package identifier for different ecosystems
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIdentifier {
    pub ecosystem: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub qualifiers: HashMap<String, String>,
    pub subpath: Option<String>,
}

impl PackageIdentifier {
    /// Create a new package identifier
    pub fn new(ecosystem: String, name: String) -> Self {
        Self {
            ecosystem,
            namespace: None,
            name,
            version: None,
            qualifiers: HashMap::new(),
            subpath: None,
        }
    }

    /// Get PURL representation
    pub fn to_purl(&self) -> String {
        format!("pkg:{}/{}", self.ecosystem, self.name)
    }
}

impl std::fmt::Display for PackageIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ecosystem, self.name)?;
        if let Some(ref namespace) = self.namespace {
            write!(f, " ({})", namespace)?;
        }
        if let Some(ref version) = self.version {
            write!(f, "@{}", version)?;
        }
        Ok(())
    }
}

/// Package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub version: String,
    pub src_name: String,
    pub src_version: String,
    pub src_release: String,
    pub src_epoch: String,
    pub arch: String,
    pub license: String,
    pub maintainer: String,
    pub homepage: String,
    pub description: String,
    pub checksum: String,
    pub file_path: String,
    pub layer: Option<Layer>,
    pub dependencies: Vec<String>,
    pub built_by: Option<String>,
    pub imported_by: Vec<String>,
    pub identifier: PackageIdentifier,
    pub custom_fields: HashMap<String, String>,
}

impl Package {
    /// Create a new package
    pub fn new(name: String, version: String, identifier: PackageIdentifier) -> Self {
        Self {
            id: format!("{}@{}", name, version),
            name,
            version,
            src_name: String::new(),
            src_version: String::new(),
            src_release: String::new(),
            src_epoch: String::new(),
            arch: String::new(),
            license: String::new(),
            maintainer: String::new(),
            homepage: String::new(),
            description: String::new(),
            checksum: String::new(),
            file_path: String::new(),
            layer: None,
            dependencies: Vec::new(),
            built_by: None,
            imported_by: Vec::new(),
            identifier,
            custom_fields: HashMap::new(),
        }
    }
}

/// Collection of packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packages {
    pub packages: Vec<Package>,
}

impl Default for Packages {
    fn default() -> Self {
        Self {
            packages: Vec::new(),
        }
    }
}

impl std::ops::Deref for Packages {
    type Target = Vec<Package>;

    fn deref(&self) -> &Self::Target {
        &self.packages
    }
}

impl std::ops::DerefMut for Packages {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.packages
    }
}

/// Application information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub r#type: String,
    pub file_path: String,
    pub libraries: Vec<Library>,
}

/// Library information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Library {
    pub library_id: String,
    pub library_name: String,
    pub library_version: String,
    pub file_path: String,
}

/// License file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    pub r#type: String,
    pub file_path: String,
    pub findings: Vec<LicenseFinding>,
}

/// License finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFinding {
    pub license: String,
    pub confidence: f64,
    pub start_line: usize,
    pub end_line: usize,
}

/// Custom resource for extensibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomResource {
    pub r#type: String,
    pub file_path: String,
    pub data: HashMap<String, String>,
}

/// Layer information for container images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub digest: String,
    pub diff_id: String,
    pub created_by: Option<String>,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.digest)
    }
}

/// Collection of layers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layers {
    pub layers: Vec<Layer>,
}

impl Default for Layers {
    fn default() -> Self {
        Self {
            layers: Vec::new(),
        }
    }
}

impl std::ops::Deref for Layers {
    type Target = Vec<Layer>;

    fn deref(&self) -> &Self::Target {
        &self.layers
    }
}

/// Cause metadata for misconfigurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CauseMetadata {
    pub resource: String,
    pub provider: String,
    pub service: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// Image configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    pub created: Option<DateTime<Utc>>,
    pub author: Option<String>,
    pub architecture: Option<String>,
    pub variant: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub config: HashMap<String, String>,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            created: None,
            author: None,
            architecture: None,
            variant: None,
            os: None,
            os_version: None,
            config: HashMap::new(),
        }
    }
}

/// Vulnerability status
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Status {
    Unknown,
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Unknown => write!(f, "unknown"),
            Status::NotAffected => write!(f, "not_affected"),
            Status::Affected => write!(f, "affected"),
            Status::Fixed => write!(f, "fixed"),
            Status::UnderInvestigation => write!(f, "under_investigation"),
        }
    }
}

impl From<String> for Status {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "not_affected" => Status::NotAffected,
            "affected" => Status::Affected,
            "fixed" => Status::Fixed,
            "under_investigation" => Status::UnderInvestigation,
            _ => Status::Unknown,
        }
    }
}

/// Data source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    pub id: SourceID,
    pub name: String,
    pub url: Option<String>,
    pub last_updated: Option<DateTime<Utc>>,
}

/// Source ID for vulnerability data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceID {
    NVD,
    Ubuntu,
    Alpine,
    RedHat,
    Debian,
    SUSE,
    Oracle,
    Amazon,
    Photon,
    Rocky,
    AlpineSecDB,
    NodejsSecurityWG,
    RubySecurity,
    PythonSoftwareFoundation,
    RustSec,
    GoVulnDB,
    GitHubSecurityAdvisory,
    Custom(String),
}

impl std::fmt::Display for SourceID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceID::NVD => write!(f, "nvd"),
            SourceID::Ubuntu => write!(f, "ubuntu"),
            SourceID::Alpine => write!(f, "alpine"),
            SourceID::RedHat => write!(f, "redhat"),
            SourceID::Debian => write!(f, "debian"),
            SourceID::SUSE => write!(f, "suse"),
            SourceID::Oracle => write!(f, "oracle"),
            SourceID::Amazon => write!(f, "amazon"),
            SourceID::Photon => write!(f, "photon"),
            SourceID::Rocky => write!(f, "rocky"),
            SourceID::AlpineSecDB => write!(f, "alpine-secdb"),
            SourceID::NodejsSecurityWG => write!(f, "nodejs-security-wg"),
            SourceID::RubySecurity => write!(f, "ruby-security"),
            SourceID::PythonSoftwareFoundation => write!(f, "python-software-foundation"),
            SourceID::RustSec => write!(f, "rustsec"),
            SourceID::GoVulnDB => write!(f, "go-vulndb"),
            SourceID::GitHubSecurityAdvisory => write!(f, "github-security-advisory"),
            SourceID::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// Artifact type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    ContainerImage,
    Filesystem,
    Repository,
    SBOM,
    Archive,
    Remote,
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactType::ContainerImage => write!(f, "container_image"),
            ArtifactType::Filesystem => write!(f, "filesystem"),
            ArtifactType::Repository => write!(f, "repository"),
            ArtifactType::SBOM => write!(f, "sbom"),
            ArtifactType::Archive => write!(f, "archive"),
            ArtifactType::Remote => write!(f, "remote"),
        }
    }
}

/// Relationship between packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub source: PackageIdentifier,
    pub target: PackageIdentifier,
    pub relationship_type: RelationshipType,
}

/// Relationship type between packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipType {
    Direct,
    Indirect,
    Root,
    DevDependency,
    Optional,
    Provided,
    Test,
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::Direct => write!(f, "direct"),
            RelationshipType::Indirect => write!(f, "indirect"),
            RelationshipType::Root => write!(f, "root"),
            RelationshipType::DevDependency => write!(f, "dev_dependency"),
            RelationshipType::Optional => write!(f, "optional"),
            RelationshipType::Provided => write!(f, "provided"),
            RelationshipType::Test => write!(f, "test"),
        }
    }
}

/// Represents the target of a security scan
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanTarget {
    /// Container image (e.g., "alpine:3.18", "nginx:latest")
    Image {
        name: String,
        registry: Option<String>,
        tag: Option<String>
    },
    /// Filesystem path
    Filesystem {
        path: String,
        recursive: bool
    },
    /// Git repository URL
    Repository {
        url: String,
        branch: Option<String>,
        commit: Option<String>
    },
    /// Kubernetes manifests
    Kubernetes {
        path: String,
        namespace: Option<String>
    },
    /// SBOM file
    Sbom {
        path: String,
        format: SbomFormat
    },
    /// Remote repository
    Remote {
        url: String,
        method: RemoteMethod
    },
}

impl std::fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanTarget::Image { name, .. } => write!(f, "image:{}", name),
            ScanTarget::Filesystem { path, .. } => write!(f, "fs:{}", path),
            ScanTarget::Repository { url, .. } => write!(f, "repo:{}", url),
            ScanTarget::Kubernetes { path, .. } => write!(f, "k8s:{}", path),
            ScanTarget::Sbom { path, .. } => write!(f, "sbom:{}", path),
            ScanTarget::Remote { url, .. } => write!(f, "remote:{}", url),
        }
    }
}

/// SBOM format types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SbomFormat {
    CycloneDX,
    SPDX,
    JSON,
}

/// Remote scanning methods
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteMethod {
    HTTP,
    HTTPS,
    SSH,
    Git,
}

/// Severity levels for security issues
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

impl Severity {
    /// Parse severity from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            "unknown" => Ok(Severity::Unknown),
            _ => Err(TypeError::InvalidSeverity(s.to_string())),
        }
    }

    /// Convert severity to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
            Severity::Unknown => "UNKNOWN",
        }
    }

    /// Get numeric score for severity
    pub fn score(&self) -> u32 {
        match self {
            Severity::Critical => 10,
            Severity::High => 8,
            Severity::Medium => 5,
            Severity::Low => 3,
            Severity::Info => 1,
            Severity::Unknown => 0,
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = TypeError;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_str(s)
    }
}

/// Scanner types for different security scanning domains
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScannerType {
    Vulnerability,
    Misconfiguration,
    Secret,
    License,
    RBAC,
    SBOM,
}

impl std::fmt::Display for ScannerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerType::Vulnerability => write!(f, "vuln"),
            ScannerType::Misconfiguration => write!(f, "misconfig"),
            ScannerType::Secret => write!(f, "secret"),
            ScannerType::License => write!(f, "license"),
            ScannerType::RBAC => write!(f, "rbac"),
            ScannerType::SBOM => write!(f, "sbom"),
        }
    }
}

/// Represents a detected security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecurityIssue {
    /// Vulnerability in a package
    Vulnerability(Vulnerability),
    /// Misconfiguration in infrastructure
    Misconfiguration(Misconfiguration),
    /// Secret or credential found
    Secret(Secret),
    /// License compliance issue
    License(LicenseIssue),
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub package_name: String,
    pub package_version: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub references: Vec<String>,
    pub fixed_version: Option<String>,
    pub published_date: Option<DateTime<Utc>>,
    pub last_modified_date: Option<DateTime<Utc>>,
    pub data_source: Option<DataSource>,
    pub file_path: Option<String>,
    pub line_number: Option<usize>,
    pub custom_fields: HashMap<String, String>,
}

/// Misconfiguration details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Misconfiguration {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub resolution: String,
    pub references: Vec<String>,
    pub file_path: String,
    pub line_range: Option<(usize, usize)>,
    pub resource_type: Option<String>,
    pub resource_name: Option<String>,
    pub custom_fields: HashMap<String, String>,
}

/// Secret detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub start_line: usize,
    pub end_line: usize,
    pub start_column: usize,
    pub end_column: usize,
    pub r#match: String,
    pub file_path: String,
    pub entropy: Option<f64>,
    pub custom_fields: HashMap<String, String>,
}

/// License compliance issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseIssue {
    pub license_name: String,
    pub package_name: String,
    pub package_version: String,
    pub compliance_status: ComplianceStatus,
    pub allowed_licenses: Vec<String>,
    pub forbidden_licenses: Vec<String>,
    pub custom_fields: HashMap<String, String>,
}

/// License compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Allowed,
    Forbidden,
    Restricted,
    Unknown,
}

/// Package type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageType {
    OS,
    Library,
    Unknown,
}

impl std::fmt::Display for PackageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageType::OS => write!(f, "os"),
            PackageType::Library => write!(f, "library"),
            PackageType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Complete scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub target: ScanTarget,
    pub timestamp: DateTime<Utc>,
    pub duration: std::time::Duration,
    pub scanner_version: String,
    pub issues: Vec<SecurityIssue>,
    pub metadata: ScanMetadata,
    pub summary: ScanSummary,
}

/// Additional metadata for scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub scanner_config: HashMap<String, String>,
    pub environment: HashMap<String, String>,
    pub custom_fields: HashMap<String, String>,
}

/// Summary statistics for scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_issues: usize,
    pub issues_by_severity: HashMap<String, usize>,
    pub issues_by_type: HashMap<String, usize>,
    pub packages_scanned: usize,
    pub files_scanned: usize,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(target: ScanTarget) -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            target,
            timestamp: Utc::now(),
            duration: std::time::Duration::default(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            issues: Vec::new(),
            metadata: ScanMetadata {
                scanner_config: HashMap::new(),
                environment: HashMap::new(),
                custom_fields: HashMap::new(),
            },
            summary: ScanSummary {
                total_issues: 0,
                issues_by_severity: HashMap::new(),
                issues_by_type: HashMap::new(),
                packages_scanned: 0,
                files_scanned: 0,
            },
        }
    }

    /// Add an issue to the scan result
    pub fn add_issue(&mut self, issue: SecurityIssue) {
        self.issues.push(issue);
        self.update_summary();
    }

    /// Get all issues
    pub fn issues(&self) -> &[SecurityIssue] {
        &self.issues
    }

    /// Get issues filtered by severity
    pub fn issues_by_severity(&self, severity: Severity) -> Vec<&SecurityIssue> {
        self.issues.iter().filter(|issue| {
            match issue {
                SecurityIssue::Vulnerability(v) => v.severity == severity,
                SecurityIssue::Misconfiguration(m) => m.severity == severity,
                SecurityIssue::Secret(s) => s.severity == severity,
                SecurityIssue::License(_) => false,
            }
        }).collect()
    }

    /// Get issues filtered by type
    pub fn issues_by_type(&self, issue_type: &str) -> Vec<&SecurityIssue> {
        self.issues.iter().filter(|issue| {
            match issue {
                SecurityIssue::Vulnerability(_) => issue_type == "vulnerability",
                SecurityIssue::Misconfiguration(_) => issue_type == "misconfiguration",
                SecurityIssue::Secret(_) => issue_type == "secret",
                SecurityIssue::License(_) => issue_type == "license",
            }
        }).collect()
    }

    /// Update summary statistics
    fn update_summary(&mut self) {
        self.summary.total_issues = self.issues.len();

        // Count by severity
        let mut severity_counts = HashMap::new();
        for issue in &self.issues {
            let severity = match issue {
                SecurityIssue::Vulnerability(v) => v.severity.as_str(),
                SecurityIssue::Misconfiguration(m) => m.severity.as_str(),
                SecurityIssue::Secret(s) => s.severity.as_str(),
                SecurityIssue::License(_) => continue,
            };
            *severity_counts.entry(severity.to_string()).or_insert(0) += 1;
        }
        self.summary.issues_by_severity = severity_counts;

        // Count by type
        let mut type_counts = HashMap::new();
        for issue in &self.issues {
            let issue_type = match issue {
                SecurityIssue::Vulnerability(_) => "vulnerability",
                SecurityIssue::Misconfiguration(_) => "misconfiguration",
                SecurityIssue::Secret(_) => "secret",
                SecurityIssue::License(_) => "license",
            };
            *type_counts.entry(issue_type.to_string()).or_insert(0) += 1;
        }
        self.summary.issues_by_type = type_counts;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("critical").unwrap(), Severity::Critical);
        assert_eq!(Severity::from_str("HIGH").unwrap(), Severity::High);
        assert_eq!(Severity::from_str("medium").unwrap(), Severity::Medium);
        assert_eq!(Severity::from_str("low").unwrap(), Severity::Low);
        assert_eq!(Severity::from_str("info").unwrap(), Severity::Info);

        assert!(Severity::from_str("invalid").is_err());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_scan_result_operations() {
        let mut result = ScanResult::new(ScanTarget::Filesystem {
            path: "/test".to_string(),
            recursive: true
        });

        let vuln = Vulnerability {
            id: "CVE-2023-1234".to_string(),
            package_name: "test-package".to_string(),
            package_version: "1.0.0".to_string(),
            severity: Severity::High,
            title: "Test vulnerability".to_string(),
            description: "Test description".to_string(),
            cvss_score: Some(7.5),
            cvss_vector: None,
            references: vec!["https://example.com".to_string()],
            fixed_version: Some("1.0.1".to_string()),
            published_date: None,
            last_modified_date: None,
            data_source: None,
            file_path: None,
            line_number: None,
            custom_fields: HashMap::new(),
        };

        result.add_issue(SecurityIssue::Vulnerability(vuln));

        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues_by_severity(Severity::High).len(), 1);
        assert_eq!(result.issues_by_type("vulnerability").len(), 1);
    }
}
