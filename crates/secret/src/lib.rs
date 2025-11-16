//! # Secret Scanning Engine
//!
//! Advanced secret and credential detection for Deepsys security scanner.
//! Provides comprehensive detection of secrets, API keys, passwords, tokens,
//! and other sensitive information across various file types and formats.
//!
//! Features:
//! - Pattern-based detection with regex rules
//! - Entropy analysis for detecting high-entropy strings
//! - Multiple detection algorithms (exact match, fuzzy match, context-aware)
//! - Support for custom detection rules
//! - False positive reduction through validation
//! - Integration with artifact analysis results

use anyhow::Result;
use async_trait::async_trait;
use deepsys_types::{Secret, SecurityIssue, Severity, ScanTarget};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod detector;
pub mod rules;
pub mod scanner;
pub mod validator;

/// Secret scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretConfig {
    /// Enable secret scanning
    pub enabled: bool,

    /// List of detection rules to use
    pub rules: Vec<SecretRule>,

    /// Custom rule files to load
    pub custom_rules: Vec<PathBuf>,

    /// Enable entropy analysis
    pub enable_entropy: bool,

    /// Entropy threshold for detection (0.0 to 8.0)
    pub entropy_threshold: f64,

    /// Minimum secret length
    pub min_length: usize,

    /// Maximum secret length
    pub max_length: usize,

    /// File patterns to include
    pub include_patterns: Vec<String>,

    /// File patterns to exclude
    pub exclude_patterns: Vec<String>,

    /// Enable parallel processing
    pub parallel: bool,

    /// Number of worker threads for parallel processing
    pub workers: usize,

    /// Enable validation of detected secrets
    pub enable_validation: bool,

    /// Validation timeout in seconds
    pub validation_timeout: u64,

    /// Allow list of file paths that should not be scanned
    pub allow_list: Vec<String>,

    /// Custom entropy calculation weights
    pub entropy_weights: EntropyWeights,
}

impl Default for SecretConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: Self::default_rules(),
            custom_rules: Vec::new(),
            enable_entropy: true,
            entropy_threshold: 3.5,
            min_length: 8,
            max_length: 200,
            include_patterns: vec![
                "**/*.py".to_string(),
                "**/*.js".to_string(),
                "**/*.ts".to_string(),
                "**/*.java".to_string(),
                "**/*.go".to_string(),
                "**/*.rs".to_string(),
                "**/*.php".to_string(),
                "**/*.rb".to_string(),
                "**/*.sh".to_string(),
                "**/*.yaml".to_string(),
                "**/*.yml".to_string(),
                "**/*.json".to_string(),
                "**/*.xml".to_string(),
                "**/*.properties".to_string(),
                "**/*.env".to_string(),
                "**/*.config".to_string(),
                "**/Dockerfile*".to_string(),
                "**/docker-compose*".to_string(),
            ],
            exclude_patterns: vec![
                "**/.git/**".to_string(),
                "**/node_modules/**".to_string(),
                "**/vendor/**".to_string(),
                "**/target/**".to_string(),
                "**/build/**".to_string(),
                "**/dist/**".to_string(),
                "**/*.min.js".to_string(),
                "**/*.min.css".to_string(),
            ],
            parallel: true,
            workers: num_cpus::get(),
            enable_validation: true,
            validation_timeout: 10,
            allow_list: Vec::new(),
            entropy_weights: EntropyWeights::default(),
        }
    }
}

/// Entropy calculation weights for different character types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyWeights {
    pub lowercase: f64,
    pub uppercase: f64,
    pub digits: f64,
    pub special: f64,
    pub unicode: f64,
}

impl Default for EntropyWeights {
    fn default() -> Self {
        Self {
            lowercase: 1.0,
            uppercase: 1.0,
            digits: 1.0,
            special: 1.5,
            unicode: 2.0,
        }
    }
}

/// Secret detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRule {
    /// Unique rule identifier
    pub id: String,

    /// Rule name
    pub name: String,

    /// Regular expression pattern
    pub pattern: String,

    /// Rule description
    pub description: String,

    /// Severity level
    pub severity: Severity,

    /// List of tags for categorization
    pub tags: Vec<String>,

    /// Whether to enable entropy checking for this rule
    pub entropy_check: bool,

    /// Whether this is a high-confidence rule
    pub high_confidence: bool,

    /// Custom validation function (if any)
    pub validator: Option<String>,

    /// Examples of what this rule detects
    pub examples: Vec<String>,

    /// False positive indicators
    pub false_positive_indicators: Vec<String>,
}

impl SecretRule {
    /// Create a new secret rule
    pub fn new(id: String, name: String, pattern: String) -> Self {
        Self {
            id,
            name,
            pattern,
            description: format!("Detects {}", name),
            severity: Severity::High,
            tags: Vec::new(),
            entropy_check: true,
            high_confidence: false,
            validator: None,
            examples: Vec::new(),
            false_positive_indicators: Vec::new(),
        }
    }

    /// Compile the regex pattern
    pub fn regex(&self) -> Result<regex::Regex> {
        regex::Regex::new(&self.pattern).map_err(|e| {
            anyhow::anyhow!("Invalid regex pattern for rule {}: {}", self.id, e)
        })
    }
}

/// Secret scanner for detecting sensitive information
pub struct SecretScanner {
    config: SecretConfig,
    rules: Vec<SecretRule>,
    compiled_rules: Vec<CompiledRule>,
}

impl SecretScanner {
    /// Create a new secret scanner
    pub async fn new(config: SecretConfig) -> Result<Self> {
        info!("Initializing secret scanner with {} rules", config.rules.len());

        let mut scanner = Self {
            config: config.clone(),
            rules: config.rules.clone(),
            compiled_rules: Vec::new(),
        };

        // Compile all rules
        scanner.compile_rules().await?;

        // Load custom rules if specified
        if !config.custom_rules.is_empty() {
            scanner.load_custom_rules().await?;
        }

        info!("Secret scanner initialized with {} compiled rules", scanner.compiled_rules.len());
        Ok(scanner)
    }

    /// Compile all rules into regex patterns
    async fn compile_rules(&mut self) -> Result<()> {
        for rule in &self.rules {
            let regex = rule.regex()?;
            self.compiled_rules.push(CompiledRule {
                rule: rule.clone(),
                regex,
            });
        }
        Ok(())
    }

    /// Load custom rules from files
    async fn load_custom_rules(&mut self) -> Result<()> {
        for rule_file in &self.config.custom_rules {
            debug!("Loading custom rules from: {:?}", rule_file);

            if rule_file.exists() {
                let content = tokio::fs::read_to_string(rule_file).await?;
                let custom_rules: Vec<SecretRule> = serde_json::from_str(&content)
                    .map_err(|e| anyhow::anyhow!("Failed to parse custom rules: {}", e))?;

                for rule in custom_rules {
                    let regex = rule.regex()?;
                    self.compiled_rules.push(CompiledRule {
                        rule: rule.clone(),
                        regex,
                    });
                    self.rules.push(rule);
                }
            } else {
                warn!("Custom rule file not found: {:?}", rule_file);
            }
        }
        Ok(())
    }

    /// Scan a target for secrets
    pub async fn scan(&self, target: ScanTarget) -> Result<Vec<SecurityIssue>> {
        info!("Starting secret scan for target: {:?}", target);

        let scan_start = std::time::Instant::now();
        let mut all_secrets = Vec::new();

        match target {
            ScanTarget::Filesystem { path, recursive: _ } => {
                let secrets = self.scan_filesystem(&path).await?;
                all_secrets.extend(secrets);
            }
            ScanTarget::Image { name, .. } => {
                // For container images, we would need to extract filesystem first
                warn!("Secret scanning for container images not yet implemented");
            }
            ScanTarget::Repository { url, .. } => {
                // For repositories, we would need to clone and scan
                warn!("Secret scanning for repositories not yet implemented");
            }
            ScanTarget::Kubernetes { path, .. } => {
                let secrets = self.scan_kubernetes_manifests(&path).await?;
                all_secrets.extend(secrets);
            }
            _ => {
                warn!("Secret scanning not supported for target type: {:?}", target);
            }
        }

        let scan_duration = scan_start.elapsed();
        info!("Secret scan completed in {:?}. Found {} secrets", scan_duration, all_secrets.len());

        Ok(all_secrets)
    }

    /// Scan filesystem for secrets
    async fn scan_filesystem(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut secrets = Vec::new();

        // Use parallel processing if enabled
        if self.config.parallel {
            secrets = self.scan_filesystem_parallel(root_path).await?;
        } else {
            secrets = self.scan_filesystem_sequential(root_path).await?;
        }

        Ok(secrets)
    }

    /// Sequential filesystem scanning
    async fn scan_filesystem_sequential(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut secrets = Vec::new();

        for entry in walkdir::WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                // Check if file should be scanned
                if self.should_scan_file(file_path) {
                    if let Ok(file_secrets) = self.scan_file(file_path).await {
                        secrets.extend(file_secrets);
                    }
                }
            }
        }

        Ok(secrets)
    }

    /// Parallel filesystem scanning
    async fn scan_filesystem_parallel(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        use rayon::prelude::*;

        // Collect all file paths first
        let file_paths: Vec<std::path::PathBuf> = walkdir::WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| self.should_scan_file(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect();

        debug!("Scanning {} files in parallel", file_paths.len());

        // Process files in parallel
        let results: Vec<Vec<SecurityIssue>> = file_paths
            .par_iter()
            .map(|file_path| {
                // Note: This is a synchronous operation in a parallel context
                // In a real implementation, you'd need to handle async in parallel context
                match self.scan_file_sync(file_path) {
                    Ok(secrets) => secrets,
                    Err(e) => {
                        warn!("Failed to scan file {:?}: {}", file_path, e);
                        Vec::new()
                    }
                }
            })
            .collect();

        // Flatten results
        Ok(results.into_iter().flatten().collect())
    }

    /// Scan a single file for secrets
    async fn scan_file(&self, file_path: &std::path::Path) -> Result<Vec<SecurityIssue>> {
        let content = tokio::fs::read_to_string(file_path).await?;

        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut secrets = Vec::new();

        // Apply each rule
        for compiled_rule in &self.compiled_rules {
            let rule_secrets = self.apply_rule_to_content(&content, file_path, &compiled_rule).await?;
            secrets.extend(rule_secrets);
        }

        // Apply entropy-based detection
        if self.config.enable_entropy {
            let entropy_secrets = self.scan_entropy(&content, file_path).await?;
            secrets.extend(entropy_secrets);
        }

        Ok(secrets)
    }

    /// Synchronous version of scan_file for parallel processing
    fn scan_file_sync(&self, file_path: &std::path::Path) -> Result<Vec<SecurityIssue>> {
        let content = std::fs::read_to_string(file_path)?;

        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut secrets = Vec::new();

        // Apply each rule
        for compiled_rule in &self.compiled_rules {
            let rule_secrets = self.apply_rule_to_content_sync(&content, file_path, &compiled_rule)?;
            secrets.extend(rule_secrets);
        }

        // Apply entropy-based detection
        if self.config.enable_entropy {
            let entropy_secrets = self.scan_entropy_sync(&content, file_path)?;
            secrets.extend(entropy_secrets);
        }

        Ok(secrets)
    }

    /// Apply a single rule to file content
    async fn apply_rule_to_content(
        &self,
        content: &str,
        file_path: &std::path::Path,
        compiled_rule: &CompiledRule,
    ) -> Result<Vec<SecurityIssue>> {
        let mut secrets = Vec::new();

        for mat in compiled_rule.regex.find_iter(content) {
            let match_text = mat.as_str();

            // Check length constraints
            if match_text.len() < self.config.min_length || match_text.len() > self.config.max_length {
                continue;
            }

            // Check entropy if enabled for this rule
            if compiled_rule.rule.entropy_check && self.config.enable_entropy {
                let entropy = self.calculate_entropy(match_text);
                if entropy < self.config.entropy_threshold {
                    continue;
                }
            }

            // Check false positive indicators
            if self.is_false_positive(match_text, &compiled_rule.rule) {
                continue;
            }

            // Validate secret if validation is enabled
            if self.config.enable_validation {
                if let Some(validator) = &compiled_rule.rule.validator {
                    if !self.validate_secret(match_text, validator).await? {
                        continue;
                    }
                }
            }

            // Create secret finding
            let secret_finding = Secret {
                rule_id: compiled_rule.rule.id.clone(),
                title: compiled_rule.rule.name.clone(),
                severity: compiled_rule.rule.severity.clone(),
                start_line: self.get_line_number(content, mat.start()),
                end_line: self.get_line_number(content, mat.end()),
                start_column: 0, // Would need more sophisticated parsing
                end_column: match_text.len(),
                match: match_text.to_string(),
                file_path: file_path.to_string_lossy().to_string(),
                entropy: Some(self.calculate_entropy(match_text)),
                custom_fields: HashMap::new(),
            };

            secrets.push(SecurityIssue::Secret(secret_finding));
        }

        Ok(secrets)
    }

    /// Synchronous version of apply_rule_to_content
    fn apply_rule_to_content_sync(
        &self,
        content: &str,
        file_path: &std::path::Path,
        compiled_rule: &CompiledRule,
    ) -> Result<Vec<SecurityIssue>> {
        let mut secrets = Vec::new();

        for mat in compiled_rule.regex.find_iter(content) {
            let match_text = mat.as_str();

            // Check length constraints
            if match_text.len() < self.config.min_length || match_text.len() > self.config.max_length {
                continue;
            }

            // Check entropy if enabled for this rule
            if compiled_rule.rule.entropy_check && self.config.enable_entropy {
                let entropy = self.calculate_entropy(match_text);
                if entropy < self.config.entropy_threshold {
                    continue;
                }
            }

            // Check false positive indicators
            if self.is_false_positive(match_text, &compiled_rule.rule) {
                continue;
            }

            // Create secret finding
            let secret_finding = Secret {
                rule_id: compiled_rule.rule.id.clone(),
                title: compiled_rule.rule.name.clone(),
                severity: compiled_rule.rule.severity.clone(),
                start_line: self.get_line_number(content, mat.start()),
                end_line: self.get_line_number(content, mat.end()),
                start_column: 0,
                end_column: match_text.len(),
                match: match_text.to_string(),
                file_path: file_path.to_string_lossy().to_string(),
                entropy: Some(self.calculate_entropy(match_text)),
                custom_fields: HashMap::new(),
            };

            secrets.push(SecurityIssue::Secret(secret_finding));
        }

        Ok(secrets)
    }

    /// Scan for high-entropy strings
    async fn scan_entropy(&self, content: &str, file_path: &std::path::Path) -> Result<Vec<SecurityIssue>> {
        let entropy_secrets = self.scan_entropy_sync(content, file_path)?;
        Ok(entropy_secrets)
    }

    /// Synchronous entropy scanning
    fn scan_entropy_sync(&self, content: &str, file_path: &std::path::Path) -> Result<Vec<SecurityIssue>> {
        let mut secrets = Vec::new();

        // Find potential high-entropy strings
        let words = content.split_whitespace();
        for word in words {
            // Skip very short or very long strings
            if word.len() < self.config.min_length || word.len() > self.config.max_length {
                continue;
            }

            // Skip strings that look like file paths, URLs, etc.
            if self.looks_like_path_or_url(word) {
                continue;
            }

            let entropy = self.calculate_entropy(word);
            if entropy >= self.config.entropy_threshold {
                debug!("High entropy detected: {} (entropy: {:.2})", word, entropy);

                let secret_finding = Secret {
                    rule_id: "entropy-analysis".to_string(),
                    title: "High Entropy String".to_string(),
                    severity: self.entropy_to_severity(entropy),
                    start_line: 1, // Would need better line detection
                    end_line: 1,
                    start_column: 0,
                    end_column: word.len(),
                    match: word.to_string(),
                    file_path: file_path.to_string_lossy().to_string(),
                    entropy: Some(entropy),
                    custom_fields: HashMap::new(),
                };

                secrets.push(SecurityIssue::Secret(secret_finding));
            }
        }

        Ok(secrets)
    }

    /// Check if a file should be scanned based on configuration
    fn should_scan_file(&self, file_path: &std::path::Path) -> bool {
        let path_str = file_path.to_string_lossy();

        // Check allow list
        for allowed in &self.config.allow_list {
            if path_str.contains(allowed) {
                return false;
            }
        }

        // Check exclude patterns
        for pattern in &self.config.exclude_patterns {
            if self.matches_pattern(&path_str, pattern) {
                return false;
            }
        }

        // Check include patterns (if any specified)
        if !self.config.include_patterns.is_empty() {
            for pattern in &self.config.include_patterns {
                if self.matches_pattern(&path_str, pattern) {
                    return true;
                }
            }
            return false;
        }

        true
    }

    /// Check if string looks like a file path or URL
    fn looks_like_path_or_url(&self, s: &str) -> bool {
        s.contains('/') || s.contains('\\') || s.starts_with("http") || s.contains("://")
    }

    /// Calculate entropy of a string
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

    /// Convert entropy value to severity
    fn entropy_to_severity(&self, entropy: f64) -> Severity {
        if entropy >= 4.5 {
            Severity::High
        } else if entropy >= 3.5 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    /// Get line number for a character position
    fn get_line_number(&self, content: &str, position: usize) -> usize {
        let mut line = 1;
        for (i, c) in content.char_indices() {
            if i >= position {
                break;
            }
            if c == '\n' {
                line += 1;
            }
        }
        line
    }

    /// Check if a match is a false positive
    fn is_false_positive(&self, match_text: &str, rule: &SecretRule) -> bool {
        for indicator in &rule.false_positive_indicators {
            if match_text.contains(indicator) {
                return true;
            }
        }

        // Check for common false positive patterns
        match_text.contains("example") ||
        match_text.contains("sample") ||
        match_text.contains("test") ||
        match_text.contains("fake") ||
        match_text.contains("placeholder") ||
        match_text.contains("lorem") ||
        match_text.contains("TODO") ||
        match_text.contains("FIXME")
    }

    /// Validate a detected secret
    async fn validate_secret(&self, secret: &str, validator: &str) -> Result<bool> {
        // Placeholder for validation logic
        // In a real implementation, this would validate the secret format
        match validator {
            "aws_access_key" => Ok(self.validate_aws_access_key(secret)),
            "github_token" => Ok(self.validate_github_token(secret)),
            "url" => Ok(self.validate_url(secret)),
            _ => Ok(true), // Unknown validator, assume valid
        }
    }

    /// Validate AWS access key format
    fn validate_aws_access_key(&self, key: &str) -> bool {
        key.starts_with("AKIA") && key.len() == 20 && key.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    }

    /// Validate GitHub token format
    fn validate_github_token(&self, token: &str) -> bool {
        token.starts_with("ghp_") && token.len() == 40 && token.chars().all(|c| c.is_ascii_alphanumeric())
    }

    /// Validate URL format
    fn validate_url(&self, url: &str) -> bool {
        url.starts_with("http://") || url.starts_with("https://")
    }

    /// Scan Kubernetes manifests for secrets
    async fn scan_kubernetes_manifests(&self, path: &str) -> Result<Vec<SecurityIssue>> {
        debug!("Scanning Kubernetes manifests in: {}", path);

        let mut secrets = Vec::new();

        // Scan YAML files for potential secrets
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                if file_path.extension().map_or(false, |ext| ext == "yaml" || ext == "yml") {
                    if let Ok(file_secrets) = self.scan_file(file_path).await {
                        secrets.extend(file_secrets);
                    }
                }
            }
        }

        Ok(secrets)
    }

    /// Pattern matching utility
    fn matches_pattern(&self, path: &str, pattern: &str) -> bool {
        if pattern.starts_with("**/") {
            path.contains(&pattern[3..])
        } else if pattern.starts_with("*.") {
            path.ends_with(&pattern[1..])
        } else {
            path.contains(pattern)
        }
    }

    /// Get default secret detection rules
    fn default_rules() -> Vec<SecretRule> {
        vec![
            SecretRule::new(
                "aws-access-key".to_string(),
                "AWS Access Key".to_string(),
                r"AKIA[0-9A-Z]{16}".to_string(),
            ).with_severity(Severity::High)
             .with_entropy_check(true)
             .with_validator("aws_access_key".to_string())
             .with_examples(vec!["AKIA1234567890ABCDEF".to_string()]),
            SecretRule::new(
                "aws-secret-key".to_string(),
                "AWS Secret Key".to_string(),
                r"[0-9A-Za-z/+]{40}".to_string(),
            ).with_severity(Severity::High)
             .with_entropy_check(true),
            SecretRule::new(
                "github-token".to_string(),
                "GitHub Token".to_string(),
                r"ghp_[0-9A-Za-z]{36}".to_string(),
            ).with_severity(Severity::High)
             .with_entropy_check(false)
             .with_validator("github_token".to_string()),
            SecretRule::new(
                "slack-token".to_string(),
                "Slack Token".to_string(),
                r"xoxb-[0-9]+-[0-9]+-[0-9A-Za-z]+".to_string(),
            ).with_severity(Severity::High),
            SecretRule::new(
                "stripe-key".to_string(),
                "Stripe API Key".to_string(),
                r"sk_[live|test]_[0-9A-Za-z]{32}".to_string(),
            ).with_severity(Severity::High),
            SecretRule::new(
                "generic-api-key".to_string(),
                "Generic API Key".to_string(),
                r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9]{32,})['\"]?".to_string(),
            ).with_severity(Severity::Medium)
             .with_entropy_check(true),
            SecretRule::new(
                "database-connection".to_string(),
                "Database Connection String".to_string(),
                r"(?i)(mongodb|mysql|postgres|redis)://[^/\s]+:[^@\s]+@[^/\s]+/?".to_string(),
            ).with_severity(Severity::High),
            SecretRule::new(
                "private-key".to_string(),
                "Private Key".to_string(),
                r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----".to_string(),
            ).with_severity(Severity::Critical),
        ].into_iter().map(|mut rule| {
            rule.false_positive_indicators = vec![
                "example".to_string(),
                "sample".to_string(),
                "test".to_string(),
                "fake".to_string(),
                "placeholder".to_string(),
                "lorem".to_string(),
                "TODO".to_string(),
                "FIXME".to_string(),
                "your-key-here".to_string(),
                "replace-me".to_string(),
            ];
            rule
        }).collect()
    }
}

/// Compiled rule with regex pattern
struct CompiledRule {
    rule: SecretRule,
    regex: regex::Regex,
}

impl SecretRule {
    /// Set severity for the rule
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Enable entropy checking
    pub fn with_entropy_check(mut self, enabled: bool) -> Self {
        self.entropy_check = enabled;
        self
    }

    /// Set validator
    pub fn with_validator(mut self, validator: String) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Add examples
    pub fn with_examples(mut self, examples: Vec<String>) -> Self {
        self.examples = examples;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_rule_creation() {
        let rule = SecretRule::new(
            "test-rule".to_string(),
            "Test Rule".to_string(),
            r"test-pattern".to_string(),
        );

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.name, "Test Rule");
        assert_eq!(rule.pattern, "test-pattern");
        assert_eq!(rule.severity, Severity::High);
    }

    #[test]
    fn test_entropy_calculation() {
        let scanner = SecretScanner::new(SecretConfig::default()).await.unwrap();

        assert_eq!(scanner.calculate_entropy(""), 0.0);
        assert!(scanner.calculate_entropy("password123") > 2.0);
        assert!(scanner.calculate_entropy("aabbcc") < 2.0); // Low entropy
        assert!(scanner.calculate_entropy("a1b2c3") > 3.0); // High entropy
    }

    #[test]
    fn test_aws_key_validation() {
        let scanner = SecretScanner::new(SecretConfig::default()).await.unwrap();

        assert!(scanner.validate_aws_access_key("AKIA1234567890ABCDEF"));
        assert!(!scanner.validate_aws_access_key("invalid-key"));
        assert!(!scanner.validate_aws_access_key("AKIA1234567890ABCD")); // Too short
    }

    #[test]
    fn test_github_token_validation() {
        let scanner = SecretScanner::new(SecretConfig::default()).await.unwrap();

        assert!(scanner.validate_github_token("ghp_1234567890abcdef1234567890abcdef12345678"));
        assert!(!scanner.validate_github_token("invalid-token"));
        assert!(!scanner.validate_github_token("ghp_too-short"));
    }

    #[test]
    fn test_default_rules() {
        let rules = SecretConfig::default().rules;

        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.id == "aws-access-key"));
        assert!(rules.iter().any(|r| r.id == "github-token"));
    }

    #[test]
    fn test_file_filtering() {
        let config = SecretConfig::default();
        let scanner = SecretScanner::new(config).await.unwrap();

        assert!(scanner.should_scan_file(std::path::Path::new("src/main.py")));
        assert!(!scanner.should_scan_file(std::path::Path::new(".git/config")));
        assert!(!scanner.should_scan_file(std::path::Path::new("node_modules/package.json")));
    }
}
