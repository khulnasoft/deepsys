//! # Default Secret Rules
//!
//! This module contains the default secret detection rules.

use deepsys_types::Severity;
use crate::SecretRule;

pub fn get_default_rules() -> Vec<SecretRule> {
    vec![
        // AWS Keys
        SecretRule {
            id: "aws-access-key".to_string(),
            name: "AWS Access Key".to_string(),
            pattern: r"AKIA[0-9A-Z]{16}".to_string(),
            description: "AWS Access Key ID".to_string(),
            severity: Severity::High,
            tags: vec!["aws".to_string(), "cloud".to_string],
            entropy_check: true,
            high_confidence: true,
            validator: Some("aws_access_key".to_string()),
            examples: vec!["AKIA1234567890ABCDEF".to_string],
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
            tags: vec!["aws".to_string(), "cloud".to_string],
            entropy_check: true,
            high_confidence: false,
            validator: None,
            examples: vec!["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0".to_string],
            false_positive_indicators: vec!["example".to_string(), "lorem".to_string],
        },

        // GitHub Tokens
        SecretRule {
            id: "github-token".to_string(),
            name: "GitHub Token".to_string(),
            pattern: r"ghp_[0-9A-Za-z]{36}".to_string(),
            description: "GitHub Personal Access Token".to_string(),
            severity: Severity::High,
            tags: vec!["github".to_string(), "git".to_string],
            entropy_check: false,
            high_confidence: true,
            validator: Some("github_token".to_string()),
            examples: vec!["ghp_1234567890abcdef1234567890abcdef12345678".to_string],
            false_positive_indicators: vec!["example".to_string(), "test".to_string],
        },
        SecretRule {
            id: "github-app-token".to_string(),
            name: "GitHub App Token".to_string(),
            pattern: r"ghs_[0-9A-Za-z]{36}".to_string(),
            description: "GitHub Server-to-Server Token".to_string(),
            severity: Severity::High,
            tags: vec!["github".to_string(), "git".to_string],
            entropy_check: false,
            high_confidence: true,
            validator: None,
            examples: vec!["ghs_1234567890abcdef1234567890abcdef12345678".to_string],
            false_positive_indicators: vec!["example".to_string],
        },

        // Slack Tokens
        SecretRule {
            id: "slack-token".to_string(),
            name: "Slack Token".to_string(),
            pattern: r"xoxb-[0-9]+-[0-9]+-[0-9A-Za-z]+".to_string(),
            description: "Slack Bot Token".to_string(),
            severity: Severity::High,
            tags: vec!["slack".to_string(), "chat".to_string],
            entropy_check: false,
            high_confidence: true,
            validator: None,
            examples: vec!["xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx".to_string],
            false_positive_indicators: vec!["example".to_string],
        },
        SecretRule {
            id: "slack-webhook".to_string(),
            name: "Slack Webhook".to_string(),
            pattern: r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+".to_string(),
            description: "Slack Webhook URL".to_string(),
            severity: Severity::Medium,
            tags: vec!["slack".to_string(), "webhook".to_string],
            entropy_check: false,
            high_confidence: true,
            validator: Some("url".to_string()),
            examples: vec!["https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX".to_string],
            false_positive_indicators: vec!["example".to_string],
        },

        // Stripe Keys
        SecretRule {
            id: "stripe-secret-key".to_string(),
            name: "Stripe Secret Key".to_string(),
            pattern: r"sk_(live|test)_[0-9a-zA-Z]{24}".to_string(),
            description: "Stripe Secret API Key".to_string(),
            severity: Severity::High,
            tags: vec!["stripe".to_string(), "payment".to_string],
            entropy_check: false,
            high_confidence: true,
            validator: None,
            examples: vec!["sk_test_1234567890abcdef1234567890abcdef12345678".to_string],
            false_positive_indicators: vec!["example".to_string],
        },
        SecretRule {
            id: "stripe-publishable-key".to_string(),
            name: "Stripe Publishable Key".to_string(),
            pattern: r"pk_(live|test)_[0-9a-zA-Z]{24}".to_string(),
            description: "Stripe Publishable API Key".to_string(),
            severity: Severity::Medium,
            tags: vec!["stripe".to_string(), "payment".to_string],
            entropy_check: false,
            high_confidence: true,
            validator: None,
            examples: vec!["pk_test_1234567890abcdef1234567890abcdef12345678".to_string],
            false_positive_indicators: vec!["example".to_string],
        },

        // Database Connection Strings
        SecretRule {
            id: "database-connection".to_string(),
            name: "Database Connection String".to_string(),
            pattern: r"(?i)(mongodb|mysql|postgres|redis)://[^/\s]+:[^@\s]+@[^/\s]+/?".to_string(),
            description: "Database connection string with credentials".to_string(),
            severity: Severity::High,
            tags: vec!["database".to_string(), "connection".to_string],
            entropy_check: false,
            high_confidence: false,
            validator: Some("url".to_string()),
            examples: vec!["mysql://user:password@localhost:3306/db".to_string],
            false_positive_indicators: vec!["example".to_string(), "localhost".to_string],
        },

        // Generic API Keys
        SecretRule {
            id: "generic-api-key".to_string(),
            name: "Generic API Key".to_string(),
            pattern: r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9+/=]{32,})['"]?" .to_string(),
            description: "Generic API key pattern".to_string(),
            severity: Severity::Medium,
            tags: vec!["api".to_string(), "generic".to_string],
            entropy_check: true,
            high_confidence: false,
            validator: None,
            examples: vec!["API_KEY = '1234567890abcdef1234567890abcdef1234567890'".to_string],
            false_positive_indicators: vec!["example".to_string(), "your-key-here".to_string],
        },

        // Private Keys
        SecretRule {
            id: "private-key-pem".to_string(),
            name: "Private Key (PEM)".to_string(),
            pattern: r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----".to_string(),
            description: "Private key in PEM format".to_string(),
            severity: Severity::Critical,
            tags: vec!["crypto".to_string(), "private-key".to_string],
            entropy_check: false,
            high_confidence: true,
            validator: None,
            examples: vec!["-----BEGIN RSA PRIVATE KEY-----".to_string],
            false_positive_indicators: vec!["example".to_string],
        },

        // JWT Tokens
        SecretRule {
            id: "jwt-token".to_string(),
            name: "JWT Token".to_string(),
            pattern: r"eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=-]+".to_string(),
            description: "JSON Web Token".to_string(),
            severity: Severity::Medium,
            tags: vec!["jwt".to_string(), "token".to_string],
            entropy_check: true,
            high_confidence: false,
            validator: None,
            examples: vec!["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string],
            false_positive_indicators: vec!["example".to_string],
        },

        // Password patterns
        SecretRule {
            id: "password-assignment".to_string(),
            name: "Password Assignment".to_string(),
            pattern: r"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]{8,})['"]?" .to_string(),
            description: "Password variable assignment".to_string(),
            severity: Severity::Medium,
            tags: vec!["password".to_string(), "auth".to_string],
            entropy_check: true,
            high_confidence: false,
            validator: None,
            examples: vec!["password = 'mySecretPassword123'".to_string],
            false_positive_indicators: vec!["example".to_string(), "changeme".to_string],
        },
    ]
}
