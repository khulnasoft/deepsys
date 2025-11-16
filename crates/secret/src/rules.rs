//! # Secret Rules
//!
//! Predefined and custom secret detection rules. Provides a comprehensive
//! set of patterns for detecting various types of secrets and credentials.

use anyhow::Result;
use deepsys_types::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::SecretRule;

/// Rule registry for managing detection rules
pub struct RuleRegistry {
    rules: HashMap<String, SecretRule>,
    rules_by_severity: HashMap<Severity, Vec<String>>,
    rules_by_tag: HashMap<String, Vec<String>>,
}

impl RuleRegistry {
    /// Create a new rule registry
    pub fn new() -> Self {
        let mut registry = Self {
            rules: HashMap::new(),
            rules_by_severity: HashMap::new(),
            rules_by_tag: HashMap::new(),
        };

        // Load default rules
        registry.load_default_rules();

        registry
    }

    /// Add a rule to the registry
    pub fn add_rule(&mut self, rule: SecretRule) {
        let rule_id = rule.id.clone();

        // Store rule
        self.rules.insert(rule_id.clone(), rule.clone());

        // Index by severity
        self.rules_by_severity
            .entry(rule.severity.clone())
            .or_insert_with(Vec::new)
            .push(rule_id.clone());

        // Index by tags
        for tag in &rule.tags {
            self.rules_by_tag
                .entry(tag.clone())
                .or_insert_with(Vec::new)
                .push(rule_id.clone());
        }
    }

    /// Get rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Option<&SecretRule> {
        self.rules.get(rule_id)
    }

    /// Get all rules
    pub fn get_all_rules(&self) -> Vec<&SecretRule> {
        self.rules.values().collect()
    }

    /// Get rules by severity
    pub fn get_rules_by_severity(&self, severity: Severity) -> Vec<&SecretRule> {
        if let Some(rule_ids) = self.rules_by_severity.get(&severity) {
            rule_ids.iter().filter_map(|id| self.rules.get(id)).collect()
        } else {
            Vec::new()
        }
    }

    /// Get rules by tag
    pub fn get_rules_by_tag(&self, tag: &str) -> Vec<&SecretRule> {
        if let Some(rule_ids) = self.rules_by_tag.get(tag) {
            rule_ids.iter().filter_map(|id| self.rules.get(id)).collect()
        } else {
            Vec::new()
        }
    }

    /// Load default rules
    fn load_default_rules(&mut self) {
        let default_rules = vec![
            // AWS Keys
            SecretRule {
                id: "aws-access-key".to_string(),
                name: "AWS Access Key".to_string(),
                pattern: r"AKIA[0-9A-Z]{16}".to_string(),
                description: "AWS Access Key ID".to_string(),
                severity: Severity::High,
                tags: vec!["aws".to_string(), "cloud".to_string()],
                entropy_check: true,
                high_confidence: true,
                validator: Some("aws_access_key".to_string()),
                examples: vec!["AKIA1234567890ABCDEF".to_string()],
                false_positive_indicators: vec![
                    "example".to_string(),
                    "sample".to_string(),
                    "test".to_string(),
                    "fake".to_string(),
                ],
            },
            SecretRule {
                id: "aws-secret-key".to_string(),
                name: "AWS Secret Key".to_string(),
                pattern: r"[0-9A-Za-z/+]{40}".to_string(),
                description: "AWS Secret Access Key".to_string(),
                severity: Severity::High,
                tags: vec!["aws".to_string(), "cloud".to_string()],
                entropy_check: true,
                high_confidence: false,
                validator: None,
                examples: vec!["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0".to_string()],
                false_positive_indicators: vec!["example".to_string(), "lorem".to_string()],
            },

            // GitHub Tokens
            SecretRule {
                id: "github-token".to_string(),
                name: "GitHub Token".to_string(),
                pattern: r"ghp_[0-9A-Za-z]{36}".to_string(),
                description: "GitHub Personal Access Token".to_string(),
                severity: Severity::High,
                tags: vec!["github".to_string(), "git".to_string()],
                entropy_check: false,
                high_confidence: true,
                validator: Some("github_token".to_string()),
                examples: vec!["ghp_1234567890abcdef1234567890abcdef12345678".to_string()],
                false_positive_indicators: vec!["example".to_string(), "test".to_string()],
            },
            SecretRule {
                id: "github-app-token".to_string(),
                name: "GitHub App Token".to_string(),
                pattern: r"ghs_[0-9A-Za-z]{36}".to_string(),
                description: "GitHub Server-to-Server Token".to_string(),
                severity: Severity::High,
                tags: vec!["github".to_string(), "git".to_string()],
                entropy_check: false,
                high_confidence: true,
                validator: None,
                examples: vec!["ghs_1234567890abcdef1234567890abcdef12345678".to_string()],
                false_positive_indicators: vec!["example".to_string()],
            },

            // Slack Tokens
            SecretRule {
                id: "slack-token".to_string(),
                name: "Slack Token".to_string(),
                pattern: r"xoxb-[0-9]+-[0-9]+-[0-9A-Za-z]+".to_string(),
                description: "Slack Bot Token".to_string(),
                severity: Severity::High,
                tags: vec!["slack".to_string(), "chat".to_string()],
                entropy_check: false,
                high_confidence: true,
                validator: None,
                examples: vec!["xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx".to_string()],
                false_positive_indicators: vec!["example".to_string()],
            },
            SecretRule {
                id: "slack-webhook".to_string(),
                name: "Slack Webhook".to_string(),
                pattern: r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+".to_string(),
                description: "Slack Webhook URL".to_string(),
                severity: Severity::Medium,
                tags: vec!["slack".to_string(), "webhook".to_string()],
                entropy_check: false,
                high_confidence: true,
                validator: Some("url".to_string()),
                examples: vec!["https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX".to_string()],
                false_positive_indicators: vec!["example".to_string()],
            },

            // Stripe Keys
            SecretRule {
                id: "stripe-secret-key".to_string(),
                name: "Stripe Secret Key".to_string(),
                pattern: r"sk_[live|test]_[0-9A-Za-z]{32}".to_string(),
                description: "Stripe Secret API Key".to_string(),
                severity: Severity::High,
                tags: vec!["stripe".to_string(), "payment".to_string()],
                entropy_check: false,
                high_confidence: true,
                validator: None,
                examples: vec!["sk_test_1234567890abcdef1234567890abcdef12345678".to_string()],
                false_positive_indicators: vec!["example".to_string()],
            },
            SecretRule {
                id: "stripe-publishable-key".to_string(),
                name: "Stripe Publishable Key".to_string(),
                pattern: r"pk_[live|test]_[0-9A-Za-z]{32}".to_string(),
                description: "Stripe Publishable API Key".to_string(),
                severity: Severity::Medium,
                tags: vec!["stripe".to_string(), "payment".to_string()],
                entropy_check: false,
                high_confidence: true,
                validator: None,
                examples: vec!["pk_test_1234567890abcdef1234567890abcdef12345678".to_string()],
                false_positive_indicators: vec!["example".to_string()],
            },

            // Database Connection Strings
            SecretRule {
                id: "database-connection".to_string(),
                name: "Database Connection String".to_string(),
                pattern: r"(?i)(mongodb|mysql|postgres|redis)://[^/\s]+:[^@\s]+@[^/\s]+/?".to_string(),
                description: "Database connection string with credentials".to_string(),
                severity: Severity::High,
                tags: vec!["database".to_string(), "connection".to_string()],
                entropy_check: false,
                high_confidence: false,
                validator: Some("url".to_string()),
                examples: vec!["mysql://user:password@localhost:3306/db".to_string()],
                false_positive_indicators: vec!["example".to_string(), "localhost".to_string()],
            },

            // Generic API Keys
            SecretRule {
                id: "generic-api-key".to_string(),
                name: "Generic API Key".to_string(),
                pattern: r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{32,})['\"]?".to_string(),
                description: "Generic API key pattern".to_string(),
                severity: Severity::Medium,
                tags: vec!["api".to_string(), "generic".to_string()],
                entropy_check: true,
                high_confidence: false,
                validator: None,
                examples: vec!["API_KEY = '1234567890abcdef1234567890abcdef1234567890'".to_string()],
                false_positive_indicators: vec!["example".to_string(), "your-key-here".to_string()],
            },

            // Private Keys
            SecretRule {
                id: "private-key-pem".to_string(),
                name: "Private Key (PEM)".to_string(),
                pattern: r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----".to_string(),
                description: "Private key in PEM format".to_string(),
                severity: Severity::Critical,
                tags: vec!["crypto".to_string(), "private-key".to_string()],
                entropy_check: false,
                high_confidence: true,
                validator: None,
                examples: vec!["-----BEGIN RSA PRIVATE KEY-----".to_string()],
                false_positive_indicators: vec!["example".to_string()],
            },

            // JWT Tokens
            SecretRule {
                id: "jwt-token".to_string(),
                name: "JWT Token".to_string(),
                pattern: r"eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=-]+".to_string(),
                description: "JSON Web Token".to_string(),
                severity: Severity::Medium,
                tags: vec!["jwt".to_string(), "token".to_string()],
                entropy_check: true,
                high_confidence: false,
                validator: None,
                examples: vec!["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string()],
                false_positive_indicators: vec!["example".to_string()],
            },

            // Password patterns
            SecretRule {
                id: "password-assignment".to_string(),
                name: "Password Assignment".to_string(),
                pattern: r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,})['\"]?".to_string(),
                description: "Password variable assignment".to_string(),
                severity: Severity::Medium,
                tags: vec!["password".to_string(), "auth".to_string()],
                entropy_check: true,
                high_confidence: false,
                validator: None,
                examples: vec!["password = 'mySecretPassword123'".to_string()],
                false_positive_indicators: vec!["example".to_string(), "changeme".to_string()],
            },
        ];

        for rule in default_rules {
            self.add_rule(rule);
        }
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Rule builder for creating custom rules
pub struct RuleBuilder {
    rule: SecretRule,
}

impl RuleBuilder {
    /// Create a new rule builder
    pub fn new(id: String, name: String, pattern: String) -> Self {
        Self {
            rule: SecretRule {
                id,
                name,
                pattern,
                description: format!("Custom rule for {}", name),
                severity: Severity::Medium,
                tags: Vec::new(),
                entropy_check: true,
                high_confidence: false,
                validator: None,
                examples: Vec::new(),
                false_positive_indicators: Vec::new(),
            },
        }
    }

    /// Set description
    pub fn with_description(mut self, description: String) -> Self {
        self.rule.description = description;
        self
    }

    /// Set severity
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.rule.severity = severity;
        self
    }

    /// Add tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.rule.tags = tags;
        self
    }

    /// Enable entropy checking
    pub fn with_entropy_check(mut self, enabled: bool) -> Self {
        self.rule.entropy_check = enabled;
        self
    }

    /// Mark as high confidence
    pub fn with_high_confidence(mut self, enabled: bool) -> Self {
        self.rule.high_confidence = enabled;
        self
    }

    /// Set validator
    pub fn with_validator(mut self, validator: String) -> Self {
        self.rule.validator = Some(validator);
        self
    }

    /// Add examples
    pub fn with_examples(mut self, examples: Vec<String>) -> Self {
        self.rule.examples = examples;
        self
    }

    /// Add false positive indicators
    pub fn with_false_positive_indicators(mut self, indicators: Vec<String>) -> Self {
        self.rule.false_positive_indicators = indicators;
        self
    }

    /// Build the rule
    pub fn build(self) -> SecretRule {
        self.rule
    }
}

/// Rule validation utilities
pub struct RuleValidator;

impl RuleValidator {
    /// Validate a regex pattern
    pub fn validate_pattern(pattern: &str) -> Result<()> {
        regex::Regex::new(pattern)?;
        Ok(())
    }

    /// Check if rule ID is valid
    pub fn validate_rule_id(id: &str) -> bool {
        !id.is_empty() &&
        id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') &&
        id.len() <= 50
    }

    /// Check if rule name is valid
    pub fn validate_rule_name(name: &str) -> bool {
        !name.is_empty() && name.len() <= 100
    }

    /// Validate severity level
    pub fn validate_severity(severity: &Severity) -> bool {
        matches!(severity, Severity::Critical | Severity::High | Severity::Medium | Severity::Low | Severity::Info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_registry() {
        let registry = RuleRegistry::new();

        assert!(registry.get_rule("aws-access-key").is_some());
        assert!(registry.get_rule("nonexistent").is_none());

        let high_severity_rules = registry.get_rules_by_severity(Severity::High);
        assert!(!high_severity_rules.is_empty());
    }

    #[test]
    fn test_rule_builder() {
        let rule = RuleBuilder::new(
            "test-rule".to_string(),
            "Test Rule".to_string(),
            r"test-pattern".to_string(),
        )
        .with_description("Test description".to_string())
        .with_severity(Severity::High)
        .with_tags(vec!["test".to_string()])
        .with_high_confidence(true)
        .build();

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.severity, Severity::High);
        assert!(rule.high_confidence);
        assert_eq!(rule.tags, vec!["test"]);
    }

    #[test]
    fn test_rule_validation() {
        assert!(RuleValidator::validate_pattern(r"test-pattern").is_ok());
        assert!(RuleValidator::validate_rule_id("test-rule"));
        assert!(!RuleValidator::validate_rule_id("test rule")); // Invalid character
        assert!(RuleValidator::validate_rule_name("Test Rule"));
        assert!(RuleValidator::validate_severity(&Severity::High));
    }
}
