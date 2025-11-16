//! Report generation for Deepsys security scanner.
//!
//! This crate provides traits and implementations for generating various types of
//! reports from scan results.

use deepsys_types::ScanResult;
use serde_json;
use std::io::Write;
use thiserror::Error;

/// Errors that can occur during report generation.
#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Failed to serialize report to JSON: {0}")]
    JsonSerializationError(#[from] serde_json::Error),
    #[error("Failed to write report: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Report generation failed: {0}")]
    GenericError(String),
}

/// Result type for report operations.
pub type Result<T> = std::result::Result<T, ReportError>;

/// Trait for report generators.
pub trait ReportGenerator {
    /// Generates a report from the given scan result and writes it to the provided writer.
    fn generate_report(&self, scan_result: &ScanResult, writer: &mut dyn Write) -> Result<()>;
}

/// A report generator that outputs scan results in JSON format.
pub struct JsonReportGenerator;

impl ReportGenerator for JsonReportGenerator {
    fn generate_report(&self, scan_result: &ScanResult, writer: &mut dyn Write) -> Result<()> {
        let json_report = serde_json::to_string_pretty(scan_result)?;
        writer.write_all(json_report.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepsys_types::{ScanTarget, Severity, Vulnerability, SecurityIssue, ScanSummary, ScanMetadata};
    use chrono::Utc;
    use uuid::Uuid;
    use std::collections::HashMap;

    #[test]
    fn test_json_report_generation() {
        let mut scan_result = ScanResult::new(ScanTarget::Filesystem {
            path: "/test".to_string(),
            recursive: true,
        });

        let vuln = Vulnerability {
            id: "CVE-TEST-001".to_string(),
            package_name: "test-package".to_string(),
            package_version: "1.0.0".to_string(),
            severity: Severity::High,
            title: "Test Vulnerability".to_string(),
            description: "A test vulnerability for JSON report.".to_string(),
            cvss_score: Some(7.5),
            cvss_vector: None,
            references: vec!["http://example.com/cve-test-001".to_string()],
            fixed_version: Some("1.0.1".to_string()),
            published_date: Some(Utc::now()),
            last_modified_date: Some(Utc::now()),
            data_source: None,
            custom_fields: HashMap::new(),
        };
        scan_result.add_issue(SecurityIssue::Vulnerability(vuln));

        let mut buffer = Vec::new();
        let generator = JsonReportGenerator;
        generator.generate_report(&scan_result, &mut buffer).unwrap();

        let report_string = String::from_utf8(buffer).unwrap();
        println!("{}", report_string); // Print for debugging/inspection

        // Basic check: ensure it's valid JSON and contains expected fields
        let parsed_report: serde_json::Value = serde_json::from_str(&report_string).unwrap();
        assert!(parsed_report["scan_id"].is_string());
        assert_eq!(parsed_report["target"]["type"], "Filesystem");
        assert_eq!(parsed_report["issues"][0]["type"], "Vulnerability");
        assert_eq!(parsed_report["issues"][0]["Vulnerability"]["id"], "CVE-TEST-001");
        assert_eq!(parsed_report["summary"]["total_issues"], 1);
    }
}