//! Integration tests for the Deepsys security scanner
//!
//! These tests validate the core functionality and integration between
//! different components of the security scanner.

use anyhow::Result;
use deepsys_types::{ScanTarget, Severity, Vulnerability, SecurityIssue};
use deepsys_sast::{Analyzer, AnalyzerGroup, analyzer::groups};
use std::collections::HashMap;

#[tokio::test]
async fn test_basic_scan_workflow() -> Result<()> {
    // Create a filesystem target
    let target = ScanTarget::Filesystem {
        path: "/tmp".to_string(),
        recursive: true,
    };

    // Create an analyzer
    let analyzer_group = groups::filesystem_analyzers();

    // Test that analyzers can be created
    assert!(!analyzer_group.all_analyzers().is_empty());

    Ok(())
}

#[tokio::test]
async fn test_vulnerability_creation() -> Result<()> {
    let vulnerability = Vulnerability {
        id: "CVE-2023-1234".to_string(),
        package_name: "test-package".to_string(),
        package_version: "1.0.0".to_string(),
        severity: Severity::High,
        title: "Test vulnerability".to_string(),
        description: "A test vulnerability for integration testing".to_string(),
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

    assert_eq!(vulnerability.id, "CVE-2023-1234");
    assert_eq!(vulnerability.severity, Severity::High);
    assert_eq!(vulnerability.cvss_score, Some(7.5));

    Ok(())
}

#[tokio::test]
async fn test_security_issue_handling() -> Result<()> {
    let vulnerability = Vulnerability {
        id: "CVE-2023-5678".to_string(),
        package_name: "test-package".to_string(),
        package_version: "1.0.0".to_string(),
        severity: Severity::Critical,
        title: "Critical test vulnerability".to_string(),
        description: "A critical vulnerability for testing".to_string(),
        cvss_score: Some(9.8),
        cvss_vector: None,
        references: vec![],
        fixed_version: None,
        published_date: None,
        last_modified_date: None,
        data_source: None,
        file_path: None,
        line_number: None,
        custom_fields: HashMap::new(),
    };

    let issue = SecurityIssue::Vulnerability(vulnerability);

    match &issue {
        SecurityIssue::Vulnerability(v) => {
            assert_eq!(v.severity, Severity::Critical);
            assert_eq!(v.id, "CVE-2023-5678");
        }
        _ => panic!("Expected vulnerability issue"),
    }

    Ok(())
}

#[tokio::test]
async fn test_scan_target_parsing() -> Result<()> {
    // Test image target
    let image_target = ScanTarget::Image {
        name: "nginx:latest".to_string(),
        registry: Some("docker.io".to_string()),
        tag: Some("latest".to_string()),
    };

    assert!(matches!(image_target, ScanTarget::Image { .. }));

    // Test filesystem target
    let fs_target = ScanTarget::Filesystem {
        path: "/tmp".to_string(),
        recursive: true,
    };

    assert!(matches!(fs_target, ScanTarget::Filesystem { .. }));

    Ok(())
}

#[tokio::test]
async fn test_severity_comparison() -> Result<()> {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);

    let vuln1 = Vulnerability {
        id: "CVE-1".to_string(),
        package_name: "pkg1".to_string(),
        package_version: "1.0.0".to_string(),
        severity: Severity::Critical,
        title: "Critical vulnerability".to_string(),
        description: "".to_string(),
        cvss_score: None,
        cvss_vector: None,
        references: vec![],
        fixed_version: None,
        published_date: None,
        last_modified_date: None,
        data_source: None,
        file_path: None,
        line_number: None,
        custom_fields: HashMap::new(),
    };

    let vuln2 = Vulnerability {
        id: "CVE-2".to_string(),
        package_name: "pkg2".to_string(),
        package_version: "1.0.0".to_string(),
        severity: Severity::High,
        title: "High vulnerability".to_string(),
        description: "".to_string(),
        cvss_score: None,
        cvss_vector: None,
        references: vec![],
        fixed_version: None,
        published_date: None,
        last_modified_date: None,
        data_source: None,
        file_path: None,
        line_number: None,
        custom_fields: HashMap::new(),
    };

    // Test that critical severity is higher than high
    assert!(vuln1.severity > vuln2.severity);

    Ok(())
}

#[tokio::test]
async fn test_package_identifier_creation() -> Result<()> {
    let identifier = deepsys_types::PackageIdentifier::new(
        "npm".to_string(),
        "lodash".to_string(),
    );

    assert_eq!(identifier.ecosystem, "npm");
    assert_eq!(identifier.name, "lodash");
    assert_eq!(identifier.to_purl(), "pkg:npm/lodash");

    Ok(())
}

#[tokio::test]
async fn test_os_detection() -> Result<()> {
    let os = deepsys_types::OS::new("debian".to_string(), "ubuntu".to_string());

    assert_eq!(os.family, "debian");
    assert_eq!(os.name, "ubuntu");
    assert_eq!(os.to_string(), "debian:ubuntu");

    Ok(())
}

#[test]
fn test_severity_score_mapping() {
    assert_eq!(Severity::Critical.score(), 10);
    assert_eq!(Severity::High.score(), 8);
    assert_eq!(Severity::Medium.score(), 5);
    assert_eq!(Severity::Low.score(), 3);
    assert_eq!(Severity::Info.score(), 1);
    assert_eq!(Severity::Unknown.score(), 0);
}

#[test]
fn test_scanner_type_conversion() {
    use deepsys_types::Scanner;

    let scanners = vec![
        Scanner::Vulnerability,
        Scanner::Secret,
        Scanner::Misconfiguration,
        Scanner::License,
    ];

    assert_eq!(scanners.len(), 4);
    assert!(matches!(scanners[0], Scanner::Vulnerability));
    assert!(matches!(scanners[1], Scanner::Secret));
}

#[tokio::test]
async fn test_analyzer_group_functionality() -> Result<()> {
    let mut group = AnalyzerGroup::new();

    // Test adding analyzers
    let os_analyzer = Box::new(deepsys_sast::analyzer::OsAnalyzer::new());
    group.add_analyzer(os_analyzer);

    // Test getting analyzers
    let os_analyzers = group.get_analyzers(deepsys_sast::analyzer::AnalyzerType::OS);
    assert_eq!(os_analyzers.len(), 1);

    // Test that no package analyzers exist
    let package_analyzers = group.get_analyzers(deepsys_sast::analyzer::AnalyzerType::Package);
    assert_eq!(package_analyzers.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_pre_configured_analyzer_groups() -> Result<()> {
    // Test image analyzers
    let image_group = groups::image_analyzers();
    assert!(!image_group.all_analyzers().is_empty());

    // Test filesystem analyzers
    let fs_group = groups::filesystem_analyzers();
    assert!(!fs_group.all_analyzers().is_empty());

    // Test kubernetes analyzers
    let k8s_group = groups::kubernetes_analyzers();
    assert!(!k8s_group.all_analyzers().is_empty());

    Ok(())
}

#[tokio::test]
async fn test_analysis_result_merging() -> Result<()> {
    // This test would validate that multiple analyzer results can be merged
    // For now, just test that AnalysisResult can be created and modified
    let mut result = deepsys_sast::analyzer::AnalysisResult::default();

    assert!(result.os.is_none());
    assert!(result.packages.is_empty());
    assert!(result.dependencies.is_empty());

    Ok(())
}

#[test]
fn test_error_handling() {
    use deepsys_types::TypeError;

    // Test error creation
    let error = TypeError::InvalidSeverity("invalid".to_string());
    assert!(error.to_string().contains("Invalid severity level"));

    let error = TypeError::InvalidVulnerabilityId("bad-id".to_string());
    assert!(error.to_string().contains("Invalid vulnerability ID"));
}

#[tokio::test]
async fn test_async_analyzer_trait() -> Result<()> {
    // Test that the Analyzer trait works with async functions
    let analyzer = deepsys_sast::analyzer::OsAnalyzer::new();

    // Test that we can call the trait methods
    let analyzer_type = analyzer.analyzer_type();
    assert_eq!(analyzer_type, deepsys_sast::analyzer::AnalyzerType::OS);

    let priority = analyzer.priority();
    assert_eq!(priority, 200);

    Ok(())
}

#[test]
fn test_type_serialization() {
    // Test that our types can be serialized/deserialized
    let vulnerability = Vulnerability {
        id: "CVE-2023-9999".to_string(),
        package_name: "test-pkg".to_string(),
        package_version: "1.0.0".to_string(),
        severity: Severity::Medium,
        title: "Test vulnerability".to_string(),
        description: "Test description".to_string(),
        cvss_score: Some(5.5),
        cvss_vector: None,
        references: vec!["https://example.com".to_string()],
        fixed_version: None,
        published_date: None,
        last_modified_date: None,
        data_source: None,
        file_path: None,
        line_number: None,
        custom_fields: HashMap::new(),
    };

    // Test serialization
    let json = serde_json::to_string(&vulnerability).unwrap();
    assert!(!json.is_empty());
    assert!(json.contains("CVE-2023-9999"));

    // Test deserialization
    let deserialized: Vulnerability = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, vulnerability.id);
    assert_eq!(deserialized.severity, vulnerability.severity);
}

#[tokio::test]
async fn test_scan_result_functionality() -> Result<()> {
    let mut result = deepsys_types::ScanResult::new(ScanTarget::Filesystem {
        path: "/test".to_string(),
        recursive: true,
    });

    // Test adding issues
    let vulnerability = Vulnerability {
        id: "CVE-2023-0001".to_string(),
        package_name: "test-package".to_string(),
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
        custom_fields: HashMap::new(),
    };

    result.add_issue(SecurityIssue::Vulnerability(vulnerability));

    assert_eq!(result.issues.len(), 1);
    assert_eq!(result.summary.total_issues, 1);

    // Test filtering by severity
    let high_issues = result.issues_by_severity(Severity::High);
    assert_eq!(high_issues.len(), 1);

    // Test filtering by type
    let vuln_issues = result.issues_by_type("vulnerability");
    assert_eq!(vuln_issues.len(), 1);

    Ok(())
}

#[test]
fn test_configuration_loading() {
    // Test that configuration can be loaded
    // This would test the config loading functionality
    // For now, just test that the types work
    let config = deepsys_cli::Config::default();

    assert_eq!(config.scanning.parallel, num_cpus::get());
    assert!(!config.scanning.skip_policy);
    assert!(!config.database.update);
}

#[test]
fn test_cli_argument_parsing() {
    // Test CLI argument parsing functionality
    // This would test the CLI parsing
    // For now, just test that the types work
    use deepsys_cli::{Cli, Commands, ScannerType, OutputFormat};

    // Test that we can create CLI structures
    let cli = Cli {
        command: Commands::Version,
        verbose: 0,
        quiet: false,
        config: None,
        format: OutputFormat::Table,
        output: None,
    };

    assert!(matches!(cli.command, Commands::Version));
    assert_eq!(cli.format, OutputFormat::Table);
}
