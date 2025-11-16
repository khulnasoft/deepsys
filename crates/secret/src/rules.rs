//! # Secret Rules
//!
//! Predefined and custom secret detection rules. Provides a comprehensive
//! set of patterns for detecting various types of secrets and credentials.

mod default_rules;

use anyhow::Result;
use deepsys_types::Severity;
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
    pub fn add_rule(&mut self, rule: SecretRule) -> Result<(), String> {
        RuleValidator::validate_rule(&rule)?;

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

        Ok(())
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
        for rule in default_rules::get_default_rules() {
            self.add_rule(rule).expect("Failed to add default rule");
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
    pub fn build(self) -> Result<SecretRule, String> {
        RuleValidator::validate_rule(&self.rule)?;
        Ok(self.rule)
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
    pub fn validate_rule_id(id: &str) -> Result<(), String> {
        if id.is_empty() {
            return Err("Rule ID cannot be empty".to_string());
        }
        if id.len() > 50 {
            return Err("Rule ID cannot be longer than 50 characters".to_string());
        }
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err("Rule ID contains invalid characters".to_string());
        }
        Ok(())
    }

    /// Check if rule name is valid
    pub fn validate_rule_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Rule name cannot be empty".to_string());
        }
        if name.len() > 100 {
            return Err("Rule name cannot be longer than 100 characters".to_string());
        }
        Ok(())
    }

    /// Validate severity level
    pub fn validate_severity(severity: &Severity) -> Result<(), String> {
        match severity {
            Severity::Critical | Severity::High | Severity::Medium | Severity::Low | Severity::Info => Ok(()),
            _ => Err(format!("Invalid severity level: {:?}", severity)),
        }
    }

    /// Validate a complete rule
    pub fn validate_rule(rule: &SecretRule) -> Result<(), String> {
        Self::validate_rule_id(&rule.id)?;
        Self::validate_rule_name(&rule.name)?;
        Self::validate_pattern(&rule.pattern).map_err(|e| e.to_string())?;
        Self::validate_severity(&rule.severity)?;
        Ok(())
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
        .build()
        .unwrap();

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.severity, Severity::High);
        assert!(rule.high_confidence);
        assert_eq!(rule.tags, vec!["test"]);
    }

    #[test]
    fn test_rule_validation() {
        assert!(RuleValidator::validate_pattern(r"test-pattern").is_ok());
        assert!(RuleValidator::validate_rule_id("test-rule").is_ok());
        assert!(RuleValidator::validate_rule_id("test_rule").is_ok());
        assert!(RuleValidator::validate_rule_id("test-rule-1").is_ok());
        assert!(RuleValidator::validate_rule_id("TEST-RULE").is_ok());
        assert!(RuleValidator::validate_rule_id(&"a".repeat(50)).is_ok());

        assert!(RuleValidator::validate_rule_id("").is_err());
        assert!(RuleValidator::validate_rule_id("test rule").is_err());
        assert!(RuleValidator::validate_rule_id("test-rule!").is_err());
        assert!(RuleValidator::validate_rule_id(&"a".repeat(51)).is_err());

        assert!(RuleValidator::validate_rule_name("Test Rule").is_ok());
        assert!(RuleValidator::validate_rule_name(&"a".repeat(100)).is_ok());

        assert!(RuleValidator::validate_rule_name("").is_err());
        assert!(RuleValidator::validate_rule_name(&"a".repeat(101)).is_err());

        assert!(RuleValidator::validate_severity(&Severity::High).is_ok());
        assert!(RuleValidator::validate_severity(&Severity::Unknown).is_err());
    }
}
