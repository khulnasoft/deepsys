//! # License Types
//!
//! License compliance types converted from Go pkg/types/license.go

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::finding::Finding;

/// License category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LicenseCategory {
    Forbidden,
    Restricted,
    Allowed,
}

impl std::fmt::Display for LicenseCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseCategory::Forbidden => write!(f, "forbidden"),
            LicenseCategory::Restricted => write!(f, "restricted"),
            LicenseCategory::Allowed => write!(f, "allowed"),
        }
    }
}

impl From<String> for LicenseCategory {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "forbidden" => LicenseCategory::Forbidden,
            "restricted" => LicenseCategory::Restricted,
            "allowed" => LicenseCategory::Allowed,
            _ => LicenseCategory::Allowed,
        }
    }
}

/// Detected license information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLicense {
    /// License file type
    pub r#type: String,

    /// License ID
    pub id: String,

    /// License name
    pub name: String,

    /// License text content
    pub text: String,

    /// SPDX license identifier
    pub spdx_id: Option<String>,

    /// License category
    pub category: LicenseCategory,

    /// File path where license was found
    pub file_path: String,

    /// Package name if applicable
    pub pkg_name: Option<String>,

    /// Package version if applicable
    pub pkg_version: Option<String>,

    /// Custom fields
    pub custom_fields: HashMap<String, String>,
}

impl Finding for DetectedLicense {
    fn finding_type(&self) -> crate::finding::FindingType {
        crate::finding::FindingType::License
    }

    fn title(&self) -> &str {
        &self.name
    }

    fn file_path(&self) -> Option<&str> {
        Some(&self.file_path)
    }
}

/// License file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    /// License type
    pub r#type: String,

    /// SPDX license identifier
    pub spdx_id: Option<String>,

    /// License category
    pub category: LicenseCategory,

    /// File path
    pub file_path: String,

    /// Package name
    pub pkg_name: String,

    /// Package version
    pub pkg_version: String,

    /// Custom fields
    pub custom_fields: HashMap<String, String>,
}

impl Finding for LicenseFile {
    fn finding_type(&self) -> crate::finding::FindingType {
        crate::finding::FindingType::License
    }

    fn title(&self) -> &str {
        &self.spdx_id.as_ref().unwrap_or(&self.r#type)
    }

    fn file_path(&self) -> Option<&str> {
        Some(&self.file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    #[test]
    fn test_license_category_display() {
        assert_eq!(format!("{}", LicenseCategory::Forbidden), "forbidden");
        assert_eq!(format!("{}", LicenseCategory::Restricted), "restricted");
        assert_eq!(format!("{}", LicenseCategory::Allowed), "allowed");
    }

    #[test]
    fn test_detected_license_implementation() {
        let license = DetectedLicense {
            r#type: "header".to_string(),
            id: "MIT".to_string(),
            name: "MIT License".to_string(),
            text: "MIT License text...".to_string(),
            spdx_id: Some("MIT".to_string()),
            category: LicenseCategory::Allowed,
            file_path: "src/main.rs".to_string(),
            pkg_name: Some("test-package".to_string()),
            pkg_version: Some("1.0.0".to_string()),
            custom_fields: HashMap::new(),
        };

        assert_eq!(license.finding_type(), crate::finding::FindingType::License);
        assert_eq!(license.title(), "MIT License");
        assert_eq!(license.file_path(), Some("src/main.rs"));
    }

    #[test]
    fn test_license_file_implementation() {
        let license_file = LicenseFile {
            r#type: "LICENSE".to_string(),
            spdx_id: Some("MIT".to_string()),
            category: LicenseCategory::Allowed,
            file_path: "LICENSE".to_string(),
            pkg_name: "test-package".to_string(),
            pkg_version: "1.0.0".to_string(),
            custom_fields: HashMap::new(),
        };

        assert_eq!(license_file.finding_type(), crate::finding::FindingType::License);
        assert_eq!(license_file.title(), "MIT");
        assert_eq!(license_file.file_path(), Some("LICENSE"));
    }
}
