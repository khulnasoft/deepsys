//! # Secret Types
//!
//! Secret detection types converted from Go pkg/types/secret.go and sast types

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// Detected secret (alias for sast SecretFinding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSecret {
    /// Rule ID that detected this secret
    pub rule_id: String,

    /// Title/description of the detection rule
    pub title: String,

    /// Match content that was detected
    pub r#match: String,

    /// File path where secret was found
    pub file_path: String,

    /// Start line number
    pub start_line: usize,

    /// End line number
    pub end_line: usize,

    /// Start column number
    pub start_column: usize,

    /// End column number
    pub end_column: usize,

    /// Entropy score of the match
    pub entropy: Option<f64>,

    /// Layer information (for container images)
    pub layer: Option<crate::Layer>,

    /// Custom fields
    pub custom_fields: std::collections::HashMap<String, String>,
}

impl Finding for DetectedSecret {
    fn finding_type(&self) -> crate::finding::FindingType {
        crate::finding::FindingType::Secret
    }

    fn title(&self) -> &str {
        &self.title
    }

    fn file_path(&self) -> Option<&str> {
        Some(&self.file_path)
    }

    fn line_number(&self) -> Option<usize> {
        Some(self.start_line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    #[test]
    fn test_detected_secret_implementation() {
        let secret = DetectedSecret {
            rule_id: "AWS001".to_string(),
            title: "AWS Access Key".to_string(),
            r#match: "AKIA1234567890ABCDEF".to_string(),
            file_path: "config.json".to_string(),
            start_line: 10,
            end_line: 10,
            start_column: 15,
            end_column: 35,
            entropy: Some(3.5),
            layer: None,
            custom_fields: std::collections::HashMap::new(),
        };

        assert_eq!(secret.finding_type(), crate::finding::FindingType::Secret);
        assert_eq!(secret.title(), "AWS Access Key");
        assert_eq!(secret.file_path(), Some("config.json"));
        assert_eq!(secret.line_number(), Some(10));
    }
}
