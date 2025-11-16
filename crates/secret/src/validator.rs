//! # Secret Validator
//!
//! Validation logic for detected secrets. Provides additional verification
//! to reduce false positives and confirm that detected strings are actually
//! valid secrets of the expected type.

use anyhow::Result;
use deepsys_types::{Secret, SecurityIssue};
use std::collections::HashMap;
use tokio::time::{timeout, Duration};

use crate::SecretRule;

/// Trait for secret validation
pub trait SecretValidator: Send + Sync {
    /// Validate a secret
    fn validate(&self, secret: &str) -> bool;

    /// Get validator name
    fn name(&self) -> &str;

    /// Get validation description
    fn description(&self) -> &str {
        self.name()
    }

    /// Check if validator supports async validation
    fn is_async(&self) -> bool {
        false
    }

    /// Async validation (if supported)
    async fn validate_async(&self, _secret: &str) -> Result<bool> {
        Ok(self.validate(_secret))
    }
}

/// AWS Access Key validator
pub struct AWSAccessKeyValidator;

impl SecretValidator for AWSAccessKeyValidator {
    fn validate(&self, secret: &str) -> bool {
        // AWS Access Key format: AKIA followed by 16 alphanumeric characters
        if !secret.starts_with("AKIA") {
            return false;
        }

        if secret.len() != 20 {
            return false;
        }

        // All characters after AKIA should be uppercase letters or digits
        secret.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    }

    fn name(&self) -> &str {
        "aws_access_key"
    }

    fn description(&self) -> &str {
        "AWS Access Key ID format validation"
    }
}

/// AWS Secret Key validator
pub struct AWSSecretKeyValidator;

impl SecretValidator for AWSSecretKeyValidator {
    fn validate(&self, secret: &str) -> bool {
        // AWS Secret Key format: 40 characters of base64-like characters
        if secret.len() != 40 {
            return false;
        }

        // Should contain only alphanumeric and + / characters (base64)
        secret.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
    }

    fn name(&self) -> &str {
        "aws_secret_key"
    }

    fn description(&self) -> &str {
        "AWS Secret Access Key format validation"
    }
}

/// GitHub Token validator
pub struct GitHubTokenValidator;

impl SecretValidator for GitHubTokenValidator {
    fn validate(&self, secret: &str) -> bool {
        // GitHub Personal Access Token: ghp_ followed by 36 alphanumeric characters
        if !secret.starts_with("ghp_") {
            return false;
        }

        if secret.len() != 40 {
            return false;
        }

        // Should contain only alphanumeric characters
        secret.chars().all(|c| c.is_alphanumeric())
    }

    fn name(&self) -> &str {
        "github_token"
    }

    fn description(&self) -> &str {
        "GitHub Personal Access Token format validation"
    }
}

/// Slack Token validator
pub struct SlackTokenValidator;

impl SecretValidator for SlackTokenValidator {
    fn validate(&self, secret: &str) -> bool {
        // Slack Bot Token: xoxb- followed by numbers and alphanumeric
        if !secret.starts_with("xoxb-") {
            return false;
        }

        // Format: xoxb-{number}-{number}-{alphanumeric}
        let parts: Vec<&str> = secret.split('-').collect();
        if parts.len() != 4 {
            return false;
        }

        // First two parts should be numeric
        if !parts[1].chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if !parts[2].chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Last part should be alphanumeric
        parts[3].chars().all(|c| c.is_alphanumeric())
    }

    fn name(&self) -> &str {
        "slack_token"
    }

    fn description(&self) -> &str {
        "Slack Bot Token format validation"
    }
}

/// Stripe API Key validator
pub struct StripeKeyValidator;

impl SecretValidator for StripeKeyValidator {
    fn validate(&self, secret: &str) -> bool {
        // Stripe keys: sk_test_ or sk_live_ or pk_test_ or pk_live_ followed by 32+ chars
        if !secret.starts_with("sk_") && !secret.starts_with("pk_") {
            return false;
        }

        // Should have test/live indicator
        if secret.len() < 8 {
            return false;
        }

        let prefix = &secret[3..];
        if !prefix.starts_with("test_") && !prefix.starts_with("live_") {
            return false;
        }

        // Should contain only alphanumeric and underscore
        secret.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    fn name(&self) -> &str {
        "stripe_key"
    }

    fn description(&self) -> &str {
        "Stripe API Key format validation"
    }
}

/// URL validator
pub struct URLValidator;

impl SecretValidator for URLValidator {
    fn validate(&self, secret: &str) -> bool {
        // Basic URL validation
        if !secret.starts_with("http://") && !secret.starts_with("https://") {
            return false;
        }

        // Should contain a domain
        let without_protocol = if secret.starts_with("https://") {
            &secret[8..]
        } else {
            &secret[7..]
        };

        without_protocol.contains('.')
    }

    fn name(&self) -> &str {
        "url"
    }

    fn description(&self) -> &str {
        "URL format validation"
    }
}

/// Database connection string validator
pub struct DatabaseConnectionValidator;

impl SecretValidator for DatabaseConnectionValidator {
    fn validate(&self, secret: &str) -> bool {
        // Common database connection patterns
        let db_patterns = [
            "mongodb://",
            "mysql://",
            "postgresql://",
            "postgres://",
            "redis://",
            "sqlite://",
        ];

        for pattern in &db_patterns {
            if secret.starts_with(pattern) {
                // Should contain credentials (user:pass@host)
                return secret.contains('@') && secret.contains(':');
            }
        }

        false
    }

    fn name(&self) -> &str {
        "database_connection"
    }

    fn description(&self) -> &str {
        "Database connection string validation"
    }
}

/// JWT Token validator
pub struct JWTValidator;

impl SecretValidator for JWTValidator {
    fn validate(&self, secret: &str) -> bool {
        // JWT format: header.payload.signature
        let parts: Vec<&str> = secret.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Each part should be base64-like
        for part in parts {
            if part.is_empty() {
                return false;
            }

            // JWT parts should contain only base64 characters
            if !part.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-') {
                return false;
            }
        }

        true
    }

    fn name(&self) -> &str {
        "jwt_token"
    }

    fn description(&self) -> &str {
        "JWT Token format validation"
    }
}

/// Generic API key validator
pub struct GenericAPIKeyValidator;

impl SecretValidator for GenericAPIKeyValidator {
    fn validate(&self, secret: &str) -> bool {
        // Generic API keys should be reasonably long and contain mixed character types
        if secret.len() < 16 {
            return false;
        }

        // Should contain at least 2 different character types
        let mut has_lower = false;
        let mut has_upper = false;
        let mut has_digit = false;
        let mut has_special = false;

        for c in secret.chars() {
            if c.is_ascii_lowercase() {
                has_lower = true;
            } else if c.is_ascii_uppercase() {
                has_upper = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            } else {
                has_special = true;
            }
        }

        let char_types = [has_lower, has_upper, has_digit, has_special].iter().filter(|&&x| x).count();
        char_types >= 2
    }

    fn name(&self) -> &str {
        "generic_api_key"
    }

    fn description(&self) -> &str {
        "Generic API key validation"
    }
}

/// Validation manager for coordinating multiple validators
pub struct ValidationManager {
    validators: HashMap<String, Box<dyn SecretValidator>>,
}

impl ValidationManager {
    /// Create a new validation manager
    pub fn new() -> Self {
        let mut manager = Self {
            validators: HashMap::new(),
        };

        // Register default validators
        manager.register_validator(Box::new(AWSAccessKeyValidator));
        manager.register_validator(Box::new(AWSSecretKeyValidator));
        manager.register_validator(Box::new(GitHubTokenValidator));
        manager.register_validator(Box::new(SlackTokenValidator));
        manager.register_validator(Box::new(StripeKeyValidator));
        manager.register_validator(Box::new(URLValidator));
        manager.register_validator(Box::new(DatabaseConnectionValidator));
        manager.register_validator(Box::new(JWTValidator));
        manager.register_validator(Box::new(GenericAPIKeyValidator));

        manager
    }

    /// Register a validator
    pub fn register_validator(&mut self, validator: Box<dyn SecretValidator>) {
        self.validators.insert(validator.name().to_string(), validator);
    }

    /// Validate a secret using the appropriate validator
    pub async fn validate_secret(&self, secret: &Secret, rule: &SecretRule) -> Result<ValidationResult> {
        let validator_name = rule.validator.as_ref().unwrap_or(&"generic".to_string());

        if let Some(validator) = self.validators.get(validator_name) {
            let start_time = std::time::Instant::now();

            let is_valid = if validator.is_async() {
                timeout(Duration::from_secs(10), validator.validate_async(&secret.match)).await
                    .unwrap_or(Ok(false))?
            } else {
                validator.validate(&secret.match)
            };

            let validation_time = start_time.elapsed();

            Ok(ValidationResult {
                is_valid,
                validator_name: validator.name().to_string(),
                validation_time,
                error: None,
            })
        } else {
            // No specific validator, use generic validation
            let validator = self.validators.get("generic_api_key").unwrap();
            let is_valid = validator.validate(&secret.match);
            let validation_time = Duration::from_millis(1);

            Ok(ValidationResult {
                is_valid,
                validator_name: "generic_api_key".to_string(),
                validation_time,
                error: None,
            })
        }
    }

    /// Get all available validators
    pub fn get_validators(&self) -> Vec<&str> {
        self.validators.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ValidationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of secret validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the secret is valid
    pub is_valid: bool,

    /// Name of the validator used
    pub validator_name: String,

    /// Time taken for validation
    pub validation_time: Duration,

    /// Any error that occurred during validation
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key_validation() {
        let validator = AWSAccessKeyValidator;

        assert!(validator.validate("AKIA1234567890ABCDEF"));
        assert!(!validator.validate("AKIA1234567890ABCD")); // Too short
        assert!(!validator.validate("akia1234567890abcdef")); // Lowercase
        assert!(!validator.validate("AKIA1234567890ABCDE")); // Too long
    }

    #[test]
    fn test_github_token_validation() {
        let validator = GitHubTokenValidator;

        assert!(validator.validate("ghp_1234567890abcdef1234567890abcdef12345678"));
        assert!(!validator.validate("ghp_1234567890abcdef1234567890abcdef1234567")); // Too short
        assert!(!validator.validate("ghs_1234567890abcdef1234567890abcdef12345678")); // Wrong prefix
    }

    #[test]
    fn test_slack_token_validation() {
        let validator = SlackTokenValidator;

        assert!(validator.validate("xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"));
        assert!(!validator.validate("xoxb-1234567890-1234567890")); // Missing last part
        assert!(!validator.validate("xoxp-1234567890-1234567890-abcdefghijklmnopqrstuvwx")); // Wrong prefix
    }

    #[test]
    fn test_jwt_validation() {
        let validator = JWTValidator;

        assert!(validator.validate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
        assert!(!validator.validate("invalid.jwt.token")); // Wrong format
        assert!(!validator.validate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")); // Missing parts
    }

    #[test]
    fn test_validation_manager() {
        let manager = ValidationManager::new();

        let validators = manager.get_validators();
        assert!(validators.contains(&"aws_access_key"));
        assert!(validators.contains(&"github_token"));
        assert!(validators.contains(&"slack_token"));
    }
}
