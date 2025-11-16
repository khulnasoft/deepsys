//! # Policy Management
//!
//! Policy loading, management, and evaluation for misconfiguration detection.
//! Supports built-in policies and custom policy definitions.

use anyhow::Result;
use deepsys_types::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info, warn};

use crate::{Policy, MisconfConfig};

/// Policy manager for handling policy collections
pub struct PolicyManager {
    policies: HashMap<String, Policy>,
    policies_by_severity: HashMap<Severity, Vec<String>>,
    policies_by_category: HashMap<String, Vec<String>>,
}

impl PolicyManager {
    /// Create a new policy manager
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            policies_by_severity: HashMap::new(),
            policies_by_category: HashMap::new(),
        }
    }

    /// Add a policy to the manager
    pub fn add_policy(&mut self, policy: Policy) {
        let policy_id = policy.id.clone();

        // Store policy
        self.policies.insert(policy_id.clone(), policy.clone());

        // Index by severity
        self.policies_by_severity
            .entry(policy.severity.clone())
            .or_insert_with(Vec::new)
            .push(policy_id.clone());

        // Index by category
        self.policies_by_category
            .entry(policy.category.clone())
            .or_insert_with(Vec::new)
            .push(policy_id.clone());

        debug!("Added policy: {}", policy_id);
    }

    /// Get policy by ID
    pub fn get_policy(&self, policy_id: &str) -> Option<&Policy> {
        self.policies.get(policy_id)
    }

    /// Get all policies
    pub fn get_all_policies(&self) -> Vec<&Policy> {
        self.policies.values().collect()
    }

    /// Get policies by severity
    pub fn get_policies_by_severity(&self, severity: Severity) -> Vec<&Policy> {
        if let Some(policy_ids) = self.policies_by_severity.get(&severity) {
            policy_ids.iter().filter_map(|id| self.policies.get(id)).collect()
        } else {
            Vec::new()
        }
    }

    /// Get policies by category
    pub fn get_policies_by_category(&self, category: &str) -> Vec<&Policy> {
        if let Some(policy_ids) = self.policies_by_category.get(category) {
            policy_ids.iter().filter_map(|id| self.policies.get(id)).collect()
        } else {
            Vec::new()
        }
    }

    /// Load policies from configuration
    pub async fn load_from_config(config: &MisconfConfig) -> Result<Self> {
        let mut manager = Self::new();

        // Load built-in policies
        manager.load_builtin_policies().await?;

        // Load policies from files
        for policy_path in &config.policies {
            manager.load_policies_from_file(policy_path).await?;
        }

        // Load policies from directories
        for policy_dir in &config.policy_dirs {
            manager.load_policies_from_directory(policy_dir).await?;
        }

        info!("Loaded {} policies", manager.policies.len());
        Ok(manager)
    }

    /// Load built-in policies
    async fn load_builtin_policies(&mut self) -> Result<()> {
        // Built-in policies are defined in the main lib.rs
        // This would typically load from embedded resources
        debug!("Loading built-in policies");
        Ok(())
    }

    /// Load policies from a file
    async fn load_policies_from_file(&mut self, _policy_path: &PathBuf) -> Result<()> {
        // Placeholder implementation
        warn!("Loading policies from files not fully implemented");
        Ok(())
    }

    /// Load policies from a directory
    async fn load_policies_from_directory(&mut self, _policy_dir: &PathBuf) -> Result<()> {
        // Placeholder implementation
        warn!("Loading policies from directories not fully implemented");
        Ok(())
    }

    /// Get manager statistics
    pub fn get_stats(&self) -> PolicyStats {
        PolicyStats {
            total_policies: self.policies.len(),
            by_severity: self.policies_by_severity.clone(),
            by_category: self.policies_by_category.clone(),
        }
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStats {
    pub total_policies: usize,
    pub by_severity: HashMap<Severity, Vec<String>>,
    pub by_category: HashMap<String, Vec<String>>,
}

/// Policy evaluator for running policies against targets
pub struct PolicyEvaluator {
    manager: PolicyManager,
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new(manager: PolicyManager) -> Self {
        Self { manager }
    }

    /// Evaluate all applicable policies against content
    pub async fn evaluate(&self, content: &str, file_path: &std::path::Path) -> Result<Vec<crate::Misconfiguration>> {
        let mut misconfigs = Vec::new();

        for policy in self.manager.get_all_policies() {
            if let Some(misconfig) = self.evaluate_single_policy(content, policy, file_path)? {
                misconfigs.push(misconfig);
            }
        }

        Ok(misconfigs)
    }

    /// Evaluate a single policy
    fn evaluate_single_policy(
        &self,
        content: &str,
        policy: &Policy,
        file_path: &std::path::Path,
    ) -> Result<Option<crate::Misconfiguration>> {
        // Simple regex-based evaluation
        if let Ok(regex) = regex::Regex::new(&policy.query) {
            if regex.is_match(content) {
                return Ok(Some(crate::Misconfiguration {
                    id: policy.id.clone(),
                    title: policy.title.clone(),
                    description: policy.description.clone(),
                    severity: policy.severity.clone(),
                    resolution: policy.resolution.clone(),
                    references: policy.references.clone(),
                    file_path: file_path.to_string_lossy().to_string(),
                    line_range: None, // Would need more sophisticated parsing
                    resource_type: Some(policy.category.clone()),
                    resource_name: None,
                    custom_fields: policy.custom_fields.clone(),
                }));
            }
        }

        Ok(None)
    }

    /// Get applicable policies for a file
    pub fn get_applicable_policies(&self, file_path: &std::path::Path) -> Vec<&Policy> {
        let mut applicable = Vec::new();

        for policy in self.manager.get_all_policies() {
            if self.policy_applies_to_file(policy, file_path) {
                applicable.push(policy);
            }
        }

        applicable
    }

    /// Check if policy applies to a file
    fn policy_applies_to_file(&self, policy: &Policy, file_path: &std::path::Path) -> bool {
        let path_str = file_path.to_string_lossy();

        // Check policy tags for file type hints
        for tag in &policy.tags {
            match tag.as_str() {
                "kubernetes" | "k8s" => {
                    if path_str.contains(".yaml") || path_str.contains(".yml") {
                        return true;
                    }
                }
                "docker" | "dockerfile" => {
                    if path_str.to_lowercase().contains("dockerfile") {
                        return true;
                    }
                }
                "terraform" | "tf" => {
                    if path_str.ends_with(".tf") || path_str.ends_with(".hcl") {
                        return true;
                    }
                }
                "cloudformation" | "cf" => {
                    if path_str.ends_with(".json") || path_str.ends_with(".yaml") || path_str.ends_with(".yml") {
                        return true;
                    }
                }
                _ => {}
            }
        }

        // Default: all policies apply
        true
    }
}

/// Custom policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPolicy {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub tags: Vec<String>,
    pub query: String,
    pub resolution: String,
    pub references: Vec<String>,
}

impl CustomPolicy {
    /// Convert to Policy
    pub fn to_policy(self) -> Policy {
        Policy {
            id: self.id,
            title: self.title,
            description: self.description,
            severity: self.severity,
            category: self.category,
            tags: self.tags,
            query: self.query,
            expected_result: None,
            resolution: self.resolution,
            references: self.references,
            custom_fields: HashMap::new(),
        }
    }
}

/// Policy validation utilities
pub struct PolicyValidator;

impl PolicyValidator {
    /// Validate policy syntax
    pub fn validate_policy(policy: &Policy) -> Result<()> {
        // Validate ID
        if policy.id.is_empty() {
            return Err(anyhow::anyhow!("Policy ID cannot be empty"));
        }

        if !policy.id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow::anyhow!("Policy ID can only contain alphanumeric characters, hyphens, and underscores"));
        }

        // Validate query (should be a valid regex)
        regex::Regex::new(&policy.query)
            .map_err(|e| anyhow::anyhow!("Invalid regex pattern: {}", e))?;

        // Validate severity
        if !matches!(policy.severity, Severity::Critical | Severity::High | Severity::Medium | Severity::Low | Severity::Info) {
            return Err(anyhow::anyhow!("Invalid severity level"));
        }

        Ok(())
    }

    /// Validate custom policy definition
    pub fn validate_custom_policy(custom_policy: &CustomPolicy) -> Result<()> {
        // Validate required fields
        if custom_policy.id.is_empty() {
            return Err(anyhow::anyhow!("Policy ID cannot be empty"));
        }

        if custom_policy.title.is_empty() {
            return Err(anyhow::anyhow!("Policy title cannot be empty"));
        }

        if custom_policy.query.is_empty() {
            return Err(anyhow::anyhow!("Policy query cannot be empty"));
        }

        // Validate regex
        regex::Regex::new(&custom_policy.query)
            .map_err(|e| anyhow::anyhow!("Invalid regex pattern: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_manager() {
        let mut manager = PolicyManager::new();

        let policy = Policy::new(
            "test-policy".to_string(),
            "Test Policy".to_string(),
            "test.*query".to_string(),
        );

        manager.add_policy(policy);

        assert!(manager.get_policy("test-policy").is_some());
        assert_eq!(manager.get_all_policies().len(), 1);
    }

    #[test]
    fn test_policy_validation() {
        let valid_policy = Policy::new(
            "test-policy".to_string(),
            "Test Policy".to_string(),
            "test.*query".to_string(),
        );

        assert!(PolicyValidator::validate_policy(&valid_policy).is_ok());

        let invalid_policy = Policy::new(
            "".to_string(),
            "Test Policy".to_string(),
            "test.*query".to_string(),
        );

        assert!(PolicyValidator::validate_policy(&invalid_policy).is_err());
    }

    #[test]
    fn test_policy_evaluator() {
        let manager = PolicyManager::new();
        let evaluator = PolicyEvaluator::new(manager);

        let applicable_policies = evaluator.get_applicable_policies(Path::new("test.yaml"));
        // Should return empty vec since no policies are loaded in test
        assert!(applicable_policies.is_empty());
    }
}
