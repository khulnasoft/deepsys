//! # Secret Detector
//!
//! Core detection algorithms for secret scanning. Provides various detection
//! methods including pattern matching, entropy analysis, and context-aware detection.

use anyhow::Result;
use deepsys_types::{Secret, SecurityIssue, Severity};
use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, trace};

use crate::{SecretRule, SecretConfig};

/// Compiled detection rule
pub struct CompiledDetector {
    pub rule: SecretRule,
    pub regex: Regex,
    pub validator: Option<Box<dyn SecretValidator>>,
}

/// Trait for secret validation
pub trait SecretValidator: Send + Sync {
    fn validate(&self, secret: &str) -> bool;
    fn name(&self) -> &str;
}

/// AWS Access Key validator
pub struct AWSAccessKeyValidator;

impl SecretValidator for AWSAccessKeyValidator {
    fn validate(&self, secret: &str) -> bool {
        secret.starts_with("AKIA") &&
        secret.len() == 20 &&
        secret.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    }

    fn name(&self) -> &str {
        "aws_access_key"
    }
}

/// GitHub Token validator
pub struct GitHubTokenValidator;

impl SecretValidator for GitHubTokenValidator {
    fn validate(&self, secret: &str) -> bool {
        secret.starts_with("ghp_") &&
        secret.len() == 40 &&
        secret.chars().all(|c| c.is_ascii_alphanumeric())
    }

    fn name(&self) -> &str {
        "github_token"
    }
}

/// URL validator
pub struct URLValidator;

impl SecretValidator for URLValidator {
    fn validate(&self, secret: &str) -> bool {
        secret.starts_with("http://") || secret.starts_with("https://")
    }

    fn name(&self) -> &str {
        "url"
    }
}

/// Entropy-based detector
pub struct EntropyDetector {
    config: SecretConfig,
}

impl EntropyDetector {
    pub fn new(config: SecretConfig) -> Self {
        Self { config }
    }

    /// Detect high-entropy strings in text
    pub fn detect(&self, content: &str) -> Vec<SecretDetection> {
        let mut detections = Vec::new();

        // Split into words and analyze each
        for word in content.split_whitespace() {
            if word.len() < self.config.min_length || word.len() > self.config.max_length {
                continue;
            }

            // Skip obvious non-secrets
            if self.looks_like_path_or_url(word) {
                continue;
            }

            let entropy = self.calculate_entropy(word);
            if entropy >= self.config.entropy_threshold {
                detections.push(SecretDetection {
                    match_text: word.to_string(),
                    entropy,
                    detection_type: DetectionType::Entropy,
                    confidence: self.entropy_to_confidence(entropy),
                    line_number: 0, // Would need line tracking
                    column_start: 0,
                    column_end: word.len(),
                });
            }
        }

        detections
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts = HashMap::new();
        let total_chars = s.chars().count() as f64;

        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let mut entropy = 0.0;
        for (_, count) in char_counts {
            let probability = count as f64 / total_chars;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn entropy_to_confidence(&self, entropy: f64) -> f64 {
        (entropy / 8.0).min(1.0) // Normalize to 0-1 range
    }

    fn looks_like_path_or_url(&self, s: &str) -> bool {
        s.contains('/') || s.contains('\\') || s.starts_with("http") || s.contains("://")
    }
}

/// Detection result
#[derive(Debug, Clone)]
pub struct SecretDetection {
    pub match_text: String,
    pub entropy: f64,
    pub detection_type: DetectionType,
    pub confidence: f64,
    pub line_number: usize,
    pub column_start: usize,
    pub column_end: usize,
}

/// Detection type
#[derive(Debug, Clone)]
pub enum DetectionType {
    Pattern,
    Entropy,
    Context,
}

/// Pattern-based detector
pub struct PatternDetector {
    detectors: Vec<CompiledDetector>,
}

impl PatternDetector {
    pub fn new(rules: Vec<SecretRule>) -> Result<Self> {
        let mut detectors = Vec::new();

        for rule in rules {
            let regex = Regex::new(&rule.pattern)?;
            let validator = Self::create_validator(&rule);

            detectors.push(CompiledDetector {
                rule,
                regex,
                validator,
            });
        }

        Ok(Self { detectors })
    }

    /// Detect secrets using pattern matching
    pub fn detect(&self, content: &str) -> Vec<SecretDetection> {
        let mut detections = Vec::new();

        for detector in &self.detectors {
            for capture in detector.regex.captures_iter(content) {
                let match_text = capture.get(0).unwrap().as_str();

                // Check length constraints
                if match_text.len() < 8 || match_text.len() > 200 {
                    continue;
                }

                // Validate if validator is available
                if let Some(ref validator) = detector.validator {
                    if !validator.validate(match_text) {
                        continue;
                    }
                }

                detections.push(SecretDetection {
                    match_text: match_text.to_string(),
                    entropy: 0.0, // Would calculate entropy
                    detection_type: DetectionType::Pattern,
                    confidence: if detector.rule.high_confidence { 0.9 } else { 0.7 },
                    line_number: 0, // Would need line tracking
                    column_start: capture.get(0).unwrap().start(),
                    column_end: capture.get(0).unwrap().end(),
                });
            }
        }

        detections
    }

    fn create_validator(rule: &SecretRule) -> Option<Box<dyn SecretValidator>> {
        match rule.validator.as_ref()?.as_str() {
            "aws_access_key" => Some(Box::new(AWSAccessKeyValidator)),
            "github_token" => Some(Box::new(GitHubTokenValidator)),
            "url" => Some(Box::new(URLValidator)),
            _ => None,
        }
    }
}

/// Context-aware detector
pub struct ContextDetector {
    config: SecretConfig,
}

impl ContextDetector {
    pub fn new(config: SecretConfig) -> Self {
        Self { config }
    }

    /// Detect secrets based on context clues
    pub fn detect(&self, content: &str, file_path: &std::path::Path) -> Vec<SecretDetection> {
        let mut detections = Vec::new();

        // Look for common secret assignment patterns
        let context_patterns = [
            (r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{16,})['\"]?".to_string(), 0.8),
            (r"(?i)(aws|github|slack|stripe)_.*\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{16,})['\"]?".to_string(), 0.9),
            (r"(?i)Bearer\s+([A-Za-z0-9+/=]{20,})".to_string(), 0.7),
        ];

        for (pattern, confidence) in &context_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for capture in regex.captures_iter(content) {
                    if let Some(secret_match) = capture.get(2) {
                        let match_text = secret_match.as_str();

                        detections.push(SecretDetection {
                            match_text: match_text.to_string(),
                            entropy: 0.0, // Would calculate
                            detection_type: DetectionType::Context,
                            confidence: *confidence,
                            line_number: 0,
                            column_start: secret_match.start(),
                            column_end: secret_match.end(),
                        });
                    }
                }
            }
        }

        detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_validator() {
        let validator = AWSAccessKeyValidator;

        assert!(validator.validate("AKIA1234567890ABCDEF"));
        assert!(!validator.validate("invalid-key"));
        assert!(!validator.validate("AKIA1234567890ABCD")); // Too short
    }

    #[test]
    fn test_github_validator() {
        let validator = GitHubTokenValidator;

        assert!(validator.validate("ghp_1234567890abcdef1234567890abcdef12345678"));
        assert!(!validator.validate("invalid-token"));
        assert!(!validator.validate("ghp_short"));
    }

    #[test]
    fn test_entropy_calculation() {
        let detector = EntropyDetector::new(SecretConfig::default());

        assert_eq!(detector.calculate_entropy(""), 0.0);
        assert!(detector.calculate_entropy("password123") > 2.0);
        assert!(detector.calculate_entropy("randomstring") > 3.0);
        assert!(detector.calculate_entropy("aabbcc") < 2.0); // Low entropy
    }

    #[test]
    fn test_context_detector() {
        let detector = ContextDetector::new(SecretConfig::default());
        let content = r#"
        API_KEY = "sk_test_1234567890abcdef1234567890abcdef12345678"
        github_token = "ghp_1234567890abcdef1234567890abcdef12345678"
        password = "mysecretpassword"
        "#;

        let detections = detector.detect(content, std::path::Path::new("test.py"));

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.match_text.contains("sk_test_")));
        assert!(detections.iter().any(|d| d.match_text.contains("ghp_")));
    }
}
