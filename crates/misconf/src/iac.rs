//! # Infrastructure as Code Detector
//!
//! Specialized detector for Infrastructure as Code (IaC) files including
//! Terraform, CloudFormation, Ansible, and other configuration management tools.

use anyhow::Result;
use deepsys_types::{Misconfiguration, SecurityIssue, Severity};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

use crate::{Policy, MisconfConfig};

/// Infrastructure as Code detector
pub struct IacDetector {
    policies: Vec<IacPolicy>,
}

impl IacDetector {
    /// Create a new IaC detector
    pub async fn new() -> Result<Self> {
        let policies = Self::get_builtin_iac_policies();

        Ok(Self { policies })
    }

    /// Scan filesystem for IaC files
    pub async fn scan_filesystem(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for entry in walkdir::WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                if self.is_iac_file(file_path) {
                    if let Ok(file_misconfigs) = self.scan_iac_file(file_path).await {
                        misconfigs.extend(file_misconfigs);
                    }
                }
            }
        }

        Ok(misconfigs)
    }

    /// Scan a single IaC file
    async fn scan_iac_file(&self, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let content = tokio::fs::read_to_string(file_path).await?;

        if self.is_terraform_file(file_path) {
            self.scan_terraform(&content, file_path).await
        } else if self.is_cloudformation_file(file_path) {
            self.scan_cloudformation(&content, file_path).await
        } else {
            self.scan_generic_iac(&content, file_path).await
        }
    }

    /// Scan Terraform configuration
    async fn scan_terraform(&self, content: &str, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        // Parse HCL content (simplified)
        let blocks = self.parse_hcl_blocks(content)?;

        for (block_type, block_name, block_content) in blocks {
            for policy in &self.policies {
                if policy.applies_to_terraform(&block_type) {
                    if let Some(misconfig) = policy.evaluate_terraform(&block_type, &block_name, &block_content, file_path)? {
                        misconfigs.push(SecurityIssue::Misconfiguration(misconfig));
                    }
                }
            }
        }

        Ok(misconfigs)
    }

    /// Scan CloudFormation template
    async fn scan_cloudformation(&self, content: &str, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let template: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| anyhow::anyhow!("Failed to parse CloudFormation: {}", e))?;

        let mut misconfigs = Vec::new();

        for policy in &self.policies {
            if policy.applies_to_cloudformation() {
                if let Some(misconfig) = policy.evaluate_cloudformation(&template, file_path)? {
                    misconfigs.push(SecurityIssue::Misconfiguration(misconfig));
                }
            }
        }

        Ok(misconfigs)
    }

    /// Scan generic IaC file
    async fn scan_generic_iac(&self, content: &str, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for policy in &self.policies {
            if policy.applies_to_generic() {
                if let Some(misconfig) = policy.evaluate_generic(content, file_path)? {
                    misconfigs.push(SecurityIssue::Misconfiguration(misconfig));
                }
            }
        }

        Ok(misconfigs)
    }

    /// Parse HCL blocks (simplified implementation)
    fn parse_hcl_blocks(&self, content: &str) -> Result<Vec<(String, String, HashMap<String, String>)>> {
        let mut blocks = Vec::new();

        // This is a very simplified HCL parser
        // In a real implementation, you'd use a proper HCL parser
        let lines: Vec<&str> = content.lines().collect();

        let mut current_block_type = String::new();
        let mut current_block_name = String::new();
        let mut current_block_content = HashMap::new();

        for line in lines {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("resource") || line.starts_with("data") || line.starts_with("provider") {
                // Save previous block if exists
                if !current_block_type.is_empty() {
                    blocks.push((current_block_type.clone(), current_block_name.clone(), current_block_content.clone()));
                }

                // Parse new block header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    current_block_type = parts[0].to_string();
                    current_block_name = format!("{} {}", parts[1], parts[2]);
                } else if parts.len() >= 2 {
                    current_block_type = parts[0].to_string();
                    current_block_name = parts[1].to_string();
                }

                current_block_content.clear();
            } else if line.starts_with('}') {
                // End of block
                if !current_block_type.is_empty() {
                    blocks.push((current_block_type.clone(), current_block_name.clone(), current_block_content.clone()));
                    current_block_type.clear();
                    current_block_name.clear();
                    current_block_content.clear();
                }
            } else if line.contains('=') && !current_block_type.is_empty() {
                // Parse attribute
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].trim().trim_matches('"').to_string();
                    let value = line[eq_pos + 1..].trim().trim_matches('"').trim_matches(',').to_string();
                    current_block_content.insert(key, value);
                }
            }
        }

        Ok(blocks)
    }

    /// Check if file is an IaC file
    fn is_iac_file(&self, file_path: &Path) -> bool {
        self.is_terraform_file(file_path) ||
        self.is_cloudformation_file(file_path) ||
        self.is_ansible_file(file_path) ||
        self.is_pulumi_file(file_path)
    }

    /// Check if file is a Terraform file
    fn is_terraform_file(&self, file_path: &Path) -> bool {
        let extension = file_path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        extension == "tf" || extension == "tfvars" || extension == "hcl"
    }

    /// Check if file is a CloudFormation file
    fn is_cloudformation_file(&self, file_path: &Path) -> bool {
        let extension = file_path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        extension == "json" || extension == "yaml" || extension == "yml"
    }

    /// Check if file is an Ansible file
    fn is_ansible_file(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        filename.ends_with(".yml") || filename.ends_with(".yaml")
    }

    /// Check if file is a Pulumi file
    fn is_pulumi_file(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        filename == "Pulumi.yaml" || filename == "Pulumi.yml"
    }

    /// Get built-in IaC security policies
    fn get_builtin_iac_policies() -> Vec<IacPolicy> {
        vec![
            IacPolicy::new(
                "iac-unencrypted-storage".to_string(),
                "Unencrypted Storage".to_string(),
                Severity::High,
                "Storage resources should be encrypted".to_string(),
                Box::new(|content: &str, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    let lower_content = content.to_lowercase();

                    if lower_content.contains("encrypted") && lower_content.contains("false") {
                        return Ok(Some(Misconfiguration {
                            id: "iac-unencrypted-storage".to_string(),
                            title: "Unencrypted Storage".to_string(),
                            description: "Storage resource is not encrypted".to_string(),
                            severity: Severity::High,
                            resolution: "Enable encryption for storage resources".to_string(),
                            references: vec!["https://docs.aws.amazon.com/".to_string()],
                            file_path: file_path.to_string_lossy().to_string(),
                            line_range: None,
                            resource_type: Some("Storage".to_string()),
                            resource_name: None,
                            custom_fields: HashMap::new(),
                        }));
                    }

                    Ok(None)
                }),
            ),
            IacPolicy::new(
                "iac-public-access".to_string(),
                "Public Access Enabled".to_string(),
                Severity::High,
                "Resources should not be publicly accessible".to_string(),
                Box::new(|content: &str, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    let lower_content = content.to_lowercase();

                    if (lower_content.contains("public") || lower_content.contains("world")) &&
                       (lower_content.contains("read") || lower_content.contains("write") || lower_content.contains("access")) {
                        return Ok(Some(Misconfiguration {
                            id: "iac-public-access".to_string(),
                            title: "Public Access Enabled".to_string(),
                            description: "Resource is configured with public access".to_string(),
                            severity: Severity::High,
                            resolution: "Disable public access for production resources".to_string(),
                            references: vec!["https://docs.aws.amazon.com/".to_string()],
                            file_path: file_path.to_string_lossy().to_string(),
                            line_range: None,
                            resource_type: Some("Network".to_string()),
                            resource_name: None,
                            custom_fields: HashMap::new(),
                        }));
                    }

                    Ok(None)
                }),
            ),
            IacPolicy::new(
                "iac-root-access".to_string(),
                "Root Access Policy".to_string(),
                Severity::High,
                "Avoid using root credentials or admin access".to_string(),
                Box::new(|content: &str, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    let lower_content = content.to_lowercase();

                    if lower_content.contains("root") || lower_content.contains("admin") || lower_content.contains("*") {
                        return Ok(Some(Misconfiguration {
                            id: "iac-root-access".to_string(),
                            title: "Root Access Policy".to_string(),
                            description: "Policy grants excessive privileges".to_string(),
                            severity: Severity::High,
                            resolution: "Use least privilege principle for access policies".to_string(),
                            references: vec!["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html".to_string()],
                            file_path: file_path.to_string_lossy().to_string(),
                            line_range: None,
                            resource_type: Some("IAM".to_string()),
                            resource_name: None,
                            custom_fields: HashMap::new(),
                        }));
                    }

                    Ok(None)
                }),
            ),
            IacPolicy::new(
                "iac-hardcoded-secrets".to_string(),
                "Hardcoded Secrets".to_string(),
                Severity::Critical,
                "Never hardcode secrets in IaC files".to_string(),
                Box::new(|content: &str, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    let lower_content = content.to_lowercase();

                    // Look for common secret patterns
                    if lower_content.contains("password") && lower_content.contains("=") ||
                       lower_content.contains("secret") && lower_content.contains("=") ||
                       lower_content.contains("key") && lower_content.contains("=") && lower_content.contains("private") {

                        return Ok(Some(Misconfiguration {
                            id: "iac-hardcoded-secrets".to_string(),
                            title: "Hardcoded Secrets".to_string(),
                            description: "Potential hardcoded secrets detected".to_string(),
                            severity: Severity::Critical,
                            resolution: "Use secrets management systems or parameter references".to_string(),
                            references: vec!["https://docs.aws.amazon.com/systems-manager/latest/userguide/param-create-prd.html".to_string()],
                            file_path: file_path.to_string_lossy().to_string(),
                            line_range: None,
                            resource_type: Some("Security".to_string()),
                            resource_name: None,
                            custom_fields: HashMap::new(),
                        }));
                    }

                    Ok(None)
                }),
            ),
            IacPolicy::new_terraform(
                "terraform-s3-bucket-public".to_string(),
                "S3 Bucket Public Access".to_string(),
                Severity::High,
                "S3 buckets should not have public access".to_string(),
                Box::new(|block_type: &str, block_name: &str, attributes: &HashMap<String, String>, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    if block_type == "resource" && block_name.starts_with("aws_s3_bucket") {
                        // Check for public access block configuration
                        let has_public_access_block = attributes.contains_key("block_public_acls") ||
                                                     attributes.contains_key("block_public_policy") ||
                                                     attributes.contains_key("ignore_public_acls") ||
                                                     attributes.contains_key("restrict_public_buckets");

                        if !has_public_access_block {
                            return Ok(Some(Misconfiguration {
                                id: "terraform-s3-bucket-public".to_string(),
                                title: "S3 Bucket Public Access".to_string(),
                                description: "S3 bucket does not have public access blocked".to_string(),
                                severity: Severity::High,
                                resolution: "Configure public access block for S3 bucket".to_string(),
                                references: vec!["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html".to_string()],
                                file_path: file_path.to_string_lossy().to_string(),
                                line_range: None,
                                resource_type: Some("aws_s3_bucket".to_string()),
                                resource_name: Some(block_name.to_string()),
                                custom_fields: HashMap::new(),
                            }));
                        }
                    }
                    Ok(None)
                }),
            ),
            IacPolicy::new_cloudformation(
                "cf-unencrypted-ebs".to_string(),
                "Unencrypted EBS Volume".to_string(),
                Severity::High,
                "EBS volumes should be encrypted".to_string(),
                Box::new(|template: &serde_json::Value, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    if let Some(resources) = template.get("Resources") {
                        if let Some(resources_obj) = resources.as_object() {
                            for (resource_name, resource_def) in resources_obj {
                                if let Some(resource_obj) = resource_def.as_object() {
                                    if let Some(properties) = resource_obj.get("Properties") {
                                        if let Some(properties_obj) = properties.as_object() {
                                            if let Some(resource_type) = resource_obj.get("Type") {
                                                if resource_type.as_str().unwrap_or("").contains("AWS::EC2::Volume") {
                                                    let encrypted = properties_obj.get("Encrypted")
                                                        .and_then(|v| v.as_bool())
                                                        .unwrap_or(false);

                                                    if !encrypted {
                                                        return Ok(Some(Misconfiguration {
                                                            id: "cf-unencrypted-ebs".to_string(),
                                                            title: "Unencrypted EBS Volume".to_string(),
                                                            description: "EBS volume is not encrypted".to_string(),
                                                            severity: Severity::High,
                                                            resolution: "Enable encryption for EBS volumes".to_string(),
                                                            references: vec!["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html".to_string()],
                                                            file_path: file_path.to_string_lossy().to_string(),
                                                            line_range: None,
                                                            resource_type: Some("AWS::EC2::Volume".to_string()),
                                                            resource_name: Some(resource_name.clone()),
                                                            custom_fields: HashMap::new(),
                                                        }));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(None)
                }),
            ),
        ]
    }
}

/// Infrastructure as Code policy
pub struct IacPolicy {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub generic_evaluator: Option<Box<dyn Fn(&str, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>>,
    pub terraform_evaluator: Option<Box<dyn Fn(&str, &str, &HashMap<String, String>, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>>,
    pub cloudformation_evaluator: Option<Box<dyn Fn(&serde_json::Value, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>>,
}

impl IacPolicy {
    /// Create a new generic IaC policy
    pub fn new(
        id: String,
        title: String,
        severity: Severity,
        description: String,
        evaluator: Box<dyn Fn(&str, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>,
    ) -> Self {
        Self {
            id,
            title,
            severity,
            description,
            generic_evaluator: Some(evaluator),
            terraform_evaluator: None,
            cloudformation_evaluator: None,
        }
    }

    /// Create a new Terraform-specific policy
    pub fn new_terraform(
        id: String,
        title: String,
        severity: Severity,
        description: String,
        evaluator: Box<dyn Fn(&str, &str, &HashMap<String, String>, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>,
    ) -> Self {
        Self {
            id,
            title,
            severity,
            description,
            generic_evaluator: None,
            terraform_evaluator: Some(evaluator),
            cloudformation_evaluator: None,
        }
    }

    /// Create a new CloudFormation-specific policy
    pub fn new_cloudformation(
        id: String,
        title: String,
        severity: Severity,
        description: String,
        evaluator: Box<dyn Fn(&serde_json::Value, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>,
    ) -> Self {
        Self {
            id,
            title,
            severity,
            description,
            generic_evaluator: None,
            terraform_evaluator: None,
            cloudformation_evaluator: Some(evaluator),
        }
    }

    /// Check if policy applies to Terraform
    pub fn applies_to_terraform(&self, block_type: &str) -> bool {
        matches!(block_type, "resource" | "data" | "provider") || self.terraform_evaluator.is_some()
    }

    /// Check if policy applies to CloudFormation
    pub fn applies_to_cloudformation(&self) -> bool {
        self.cloudformation_evaluator.is_some()
    }

    /// Check if policy applies to generic IaC
    pub fn applies_to_generic(&self) -> bool {
        self.generic_evaluator.is_some()
    }

    /// Evaluate policy against Terraform
    pub fn evaluate_terraform(
        &self,
        block_type: &str,
        block_name: &str,
        attributes: &HashMap<String, String>,
        file_path: &Path,
    ) -> Result<Option<Misconfiguration>> {
        if let Some(ref evaluator) = self.terraform_evaluator {
            evaluator(block_type, block_name, attributes, file_path)
        } else {
            Ok(None)
        }
    }

    /// Evaluate policy against CloudFormation
    pub fn evaluate_cloudformation(
        &self,
        template: &serde_json::Value,
        file_path: &Path,
    ) -> Result<Option<Misconfiguration>> {
        if let Some(ref evaluator) = self.cloudformation_evaluator {
            evaluator(template, file_path)
        } else {
            Ok(None)
        }
    }

    /// Evaluate policy against generic IaC
    pub fn evaluate_generic(
        &self,
        content: &str,
        file_path: &Path,
    ) -> Result<Option<Misconfiguration>> {
        if let Some(ref evaluator) = self.generic_evaluator {
            evaluator(content, file_path)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hcl_parsing() {
        let detector = IacDetector {
            policies: Vec::new(),
        };

        let terraform_content = r#"
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
"#;

        let blocks = detector.parse_hcl_blocks(terraform_content).unwrap();

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, "resource");
        assert!(blocks[0].1.contains("aws_s3_bucket"));
        assert!(blocks[1].1.contains("aws_instance"));
    }

    #[test]
    fn test_is_iac_file() {
        let detector = IacDetector {
            policies: Vec::new(),
        };

        assert!(detector.is_terraform_file(Path::new("main.tf")));
        assert!(detector.is_terraform_file(Path::new("variables.tfvars")));
        assert!(detector.is_cloudformation_file(Path::new("template.json")));
        assert!(detector.is_cloudformation_file(Path::new("template.yaml")));
        assert!(!detector.is_iac_file(Path::new("README.md")));
    }

    #[test]
    fn test_cloudformation_parsing() {
        let json = r#"
{
  "Resources": {
    "MyVolume": {
      "Type": "AWS::EC2::Volume",
      "Properties": {
        "Size": "100",
        "Encrypted": false
      }
    }
  }
}
"#;

        let template: serde_json::Value = serde_json::from_str(json).unwrap();

        if let Some(resources) = template.get("Resources") {
            if let Some(resources_obj) = resources.as_object() {
                if let Some(volume) = resources_obj.get("MyVolume") {
                    if let Some(properties) = volume.get("Properties") {
                        assert_eq!(properties.get("Encrypted").unwrap().as_bool().unwrap(), false);
                    }
                }
            }
        }
    }
}
