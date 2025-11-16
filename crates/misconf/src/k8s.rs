//! # Kubernetes Misconfiguration Detector
//!
//! Specialized detector for Kubernetes manifests and configurations.
//! Identifies security misconfigurations, best practice violations,
//! and compliance issues in Kubernetes YAML files.

use anyhow::Result;
use deepsys_types::{Misconfiguration, SecurityIssue, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

use crate::{Policy, MisconfConfig};

/// Kubernetes detector for manifest analysis
pub struct K8sDetector {
    policies: Vec<K8sPolicy>,
}

impl K8sDetector {
    /// Create a new Kubernetes detector
    pub async fn new() -> Result<Self> {
        let policies = Self::get_builtin_k8s_policies();

        Ok(Self { policies })
    }

    /// Scan a filesystem path for Kubernetes manifests
    pub async fn scan_filesystem(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for entry in walkdir::WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                if self.is_k8s_manifest(file_path) {
                    if let Ok(file_misconfigs) = self.scan_k8s_file(file_path).await {
                        misconfigs.extend(file_misconfigs);
                    }
                }
            }
        }

        Ok(misconfigs)
    }

    /// Scan a specific path for Kubernetes manifests
    pub async fn scan_path(&self, path: &str) -> Result<Vec<SecurityIssue>> {
        if Path::new(path).is_file() {
            self.scan_k8s_file(Path::new(path)).await
        } else {
            self.scan_filesystem(path).await
        }
    }

    /// Scan a single Kubernetes file
    async fn scan_k8s_file(&self, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let content = tokio::fs::read_to_string(file_path).await?;
        let manifests = self.parse_k8s_manifests(&content)?;

        let mut misconfigs = Vec::new();

        for (i, manifest) in manifests.iter().enumerate() {
            let manifest_misconfigs = self.analyze_manifest(manifest, file_path, i + 1).await?;
            misconfigs.extend(manifest_misconfigs);
        }

        Ok(misconfigs)
    }

    /// Parse Kubernetes YAML content into manifests
    fn parse_k8s_manifests(&self, content: &str) -> Result<Vec<K8sManifest>> {
        let mut manifests = Vec::new();

        // Split YAML documents (separated by ---)
        for doc in content.split("---") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }

            match serde_yaml::from_str::<serde_yaml::Value>(doc) {
                Ok(value) => {
                    if let Some(manifest) = K8sManifest::from_yaml_value(value) {
                        manifests.push(manifest);
                    }
                }
                Err(e) => {
                    warn!("Failed to parse Kubernetes manifest: {}", e);
                }
            }
        }

        Ok(manifests)
    }

    /// Analyze a single Kubernetes manifest
    async fn analyze_manifest(
        &self,
        manifest: &K8sManifest,
        file_path: &Path,
        manifest_index: usize,
    ) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for policy in &self.policies {
            if policy.applies_to(manifest) {
                if let Some(misconfig) = policy.evaluate(manifest, file_path, manifest_index)? {
                    misconfigs.push(SecurityIssue::Misconfiguration(misconfig));
                }
            }
        }

        Ok(misconfigs)
    }

    /// Check if file is a Kubernetes manifest
    fn is_k8s_manifest(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension() {
            if extension == "yaml" || extension == "yml" {
                return true;
            }
        }

        // Check filename patterns
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        filename.contains("deployment") ||
        filename.contains("service") ||
        filename.contains("configmap") ||
        filename.contains("secret") ||
        filename.contains("ingress") ||
        filename.contains("pod") ||
        filename.contains("job") ||
        filename.contains("cronjob")
    }

    /// Get built-in Kubernetes security policies
    fn get_builtin_k8s_policies() -> Vec<K8sPolicy> {
        vec![
            K8sPolicy::new(
                "k8s-privileged-container".to_string(),
                "Privileged Container".to_string(),
                Severity::High,
                r#"
                Check if any container runs in privileged mode.
                Privileged containers have access to all Linux kernel capabilities.
                "#.to_string(),
                Box::new(|manifest: &K8sManifest| -> Result<Option<Misconfiguration>> {
                    if let Some(containers) = &manifest.spec.get("containers") {
                        if let Some(containers_array) = containers.as_array() {
                            for container in containers_array {
                                if let Some(security_context) = container.get("securityContext") {
                                    if let Some(privileged) = security_context.get("privileged") {
                                        if privileged.as_bool().unwrap_or(false) {
                                            return Ok(Some(Misconfiguration {
                                                id: "k8s-privileged-container".to_string(),
                                                title: "Privileged Container".to_string(),
                                                description: "Container is running in privileged mode".to_string(),
                                                severity: Severity::High,
                                                resolution: "Remove privileged: true from container security context".to_string(),
                                                references: vec!["https://kubernetes.io/docs/concepts/policy/pod-security-policy/".to_string()],
                                                file_path: manifest.metadata.name.clone(),
                                                line_range: None,
                                                resource_type: Some("Pod".to_string()),
                                                resource_name: manifest.metadata.name.clone(),
                                                custom_fields: HashMap::new(),
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(None)
                }),
            ),
            K8sPolicy::new(
                "k8s-root-filesystem-readonly".to_string(),
                "Root Filesystem Read-Only".to_string(),
                Severity::Medium,
                r#"
                Check if containers have read-only root filesystem.
                This prevents containers from writing to the root filesystem.
                "#.to_string(),
                Box::new(|manifest: &K8sManifest| -> Result<Option<Misconfiguration>> {
                    if let Some(containers) = &manifest.spec.get("containers") {
                        if let Some(containers_array) = containers.as_array() {
                            for container in containers_array {
                                if let Some(security_context) = container.get("securityContext") {
                                    let read_only = security_context
                                        .get("readOnlyRootFilesystem")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    if !read_only {
                                        return Ok(Some(Misconfiguration {
                                            id: "k8s-root-filesystem-readonly".to_string(),
                                            title: "Root Filesystem Read-Only".to_string(),
                                            description: "Container does not have read-only root filesystem".to_string(),
                                            severity: Severity::Medium,
                                            resolution: "Set readOnlyRootFilesystem: true in container security context".to_string(),
                                            references: vec!["https://kubernetes.io/docs/concepts/policy/pod-security-policy/".to_string()],
                                            file_path: manifest.metadata.name.clone(),
                                            line_range: None,
                                            resource_type: Some("Pod".to_string()),
                                            resource_name: manifest.metadata.name.clone(),
                                            custom_fields: HashMap::new(),
                                        }));
                                    }
                                }
                            }
                        }
                    }
                    Ok(None)
                }),
            ),
            K8sPolicy::new(
                "k8s-dangerous-capabilities".to_string(),
                "Dangerous Capabilities".to_string(),
                Severity::High,
                r#"
                Check for dangerous Linux capabilities that could compromise security.
                "#.to_string(),
                Box::new(|manifest: &K8sManifest| -> Result<Option<Misconfiguration>> {
                    let dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE"];

                    if let Some(containers) = &manifest.spec.get("containers") {
                        if let Some(containers_array) = containers.as_array() {
                            for container in containers_array {
                                if let Some(security_context) = container.get("securityContext") {
                                    if let Some(capabilities) = security_context.get("capabilities") {
                                        if let Some(add) = capabilities.get("add") {
                                            if let Some(caps_array) = add.as_array() {
                                                for cap in caps_array {
                                                    if let Some(cap_str) = cap.as_str() {
                                                        if dangerous_caps.contains(&cap_str) {
                                                            return Ok(Some(Misconfiguration {
                                                                id: "k8s-dangerous-capabilities".to_string(),
                                                                title: "Dangerous Capabilities".to_string(),
                                                                description: format!("Container has dangerous capability: {}", cap_str),
                                                                severity: Severity::High,
                                                                resolution: format!("Remove dangerous capability: {}", cap_str),
                                                                references: vec!["https://kubernetes.io/docs/concepts/policy/pod-security-policy/".to_string()],
                                                                file_path: manifest.metadata.name.clone(),
                                                                line_range: None,
                                                                resource_type: Some("Pod".to_string()),
                                                                resource_name: manifest.metadata.name.clone(),
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
                    }
                    Ok(None)
                }),
            ),
            K8sPolicy::new(
                "k8s-resource-limits".to_string(),
                "Missing Resource Limits".to_string(),
                Severity::Low,
                r#"
                Check if containers have resource limits defined.
                Resource limits prevent resource exhaustion attacks.
                "#.to_string(),
                Box::new(|manifest: &K8sManifest| -> Result<Option<Misconfiguration>> {
                    if let Some(containers) = &manifest.spec.get("containers") {
                        if let Some(containers_array) = containers.as_array() {
                            for container in containers_array {
                                let has_limits = container.get("resources")
                                    .and_then(|r| r.get("limits"))
                                    .is_some();

                                if !has_limits {
                                    return Ok(Some(Misconfiguration {
                                        id: "k8s-resource-limits".to_string(),
                                        title: "Missing Resource Limits".to_string(),
                                        description: "Container does not have resource limits defined".to_string(),
                                        severity: Severity::Low,
                                        resolution: "Add resource limits to container spec".to_string(),
                                        references: vec!["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/".to_string()],
                                        file_path: manifest.metadata.name.clone(),
                                        line_range: None,
                                        resource_type: Some("Pod".to_string()),
                                        resource_name: manifest.metadata.name.clone(),
                                        custom_fields: HashMap::new(),
                                    }));
                                }
                            }
                        }
                    }
                    Ok(None)
                }),
            ),
            K8sPolicy::new(
                "k8s-security-context".to_string(),
                "Missing Security Context".to_string(),
                Severity::Low,
                r#"
                Check if pods have security context defined.
                Security context provides additional security settings.
                "#.to_string(),
                Box::new(|manifest: &K8sManifest| -> Result<Option<Misconfiguration>> {
                    let has_pod_security_context = manifest.spec.get("securityContext").is_some();

                    if !has_pod_security_context {
                        return Ok(Some(Misconfiguration {
                            id: "k8s-security-context".to_string(),
                            title: "Missing Security Context".to_string(),
                            description: "Pod does not have security context defined".to_string(),
                            severity: Severity::Low,
                            resolution: "Add security context to pod spec".to_string(),
                            references: vec!["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/".to_string()],
                            file_path: manifest.metadata.name.clone(),
                            line_range: None,
                            resource_type: Some("Pod".to_string()),
                            resource_name: manifest.metadata.name.clone(),
                            custom_fields: HashMap::new(),
                        }));
                    }
                    Ok(None)
                }),
            ),
        ]
    }
}

/// Kubernetes manifest representation
#[derive(Debug, Clone)]
pub struct K8sManifest {
    pub api_version: String,
    pub kind: String,
    pub metadata: K8sMetadata,
    pub spec: serde_yaml::Value,
}

/// Kubernetes metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sMetadata {
    pub name: String,
    pub namespace: Option<String>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

impl K8sManifest {
    /// Create manifest from YAML value
    pub fn from_yaml_value(value: serde_yaml::Value) -> Option<Self> {
        let obj = value.as_mapping()?;

        let api_version = obj.get(&serde_yaml::Value::String("apiVersion".to_string()))?
            .as_str()?
            .to_string();

        let kind = obj.get(&serde_yaml::Value::String("kind".to_string()))?
            .as_str()?
            .to_string();

        let metadata = obj.get(&serde_yaml::Value::String("metadata".to_string()))?;
        let metadata: K8sMetadata = serde_yaml::from_value(metadata.clone()).ok()?;

        let spec = obj.get(&serde_yaml::Value::String("spec".to_string()))?
            .clone();

        Some(Self {
            api_version,
            kind,
            metadata,
            spec,
        })
    }

    /// Check if manifest is a workload resource
    pub fn is_workload(&self) -> bool {
        matches!(self.kind.as_str(),
            "Pod" | "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob"
        )
    }

    /// Check if manifest is a networking resource
    pub fn is_networking(&self) -> bool {
        matches!(self.kind.as_str(),
            "Service" | "Ingress" | "NetworkPolicy"
        )
    }

    /// Check if manifest is a configuration resource
    pub fn is_config(&self) -> bool {
        matches!(self.kind.as_str(),
            "ConfigMap" | "Secret"
        )
    }
}

/// Kubernetes-specific policy
pub struct K8sPolicy {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub evaluator: Box<dyn Fn(&K8sManifest) -> Result<Option<Misconfiguration>> + Send + Sync>,
}

impl K8sPolicy {
    /// Create a new Kubernetes policy
    pub fn new(
        id: String,
        title: String,
        severity: Severity,
        description: String,
        evaluator: Box<dyn Fn(&K8sManifest) -> Result<Option<Misconfiguration>> + Send + Sync>,
    ) -> Self {
        Self {
            id,
            title,
            severity,
            description,
            evaluator,
        }
    }

    /// Check if policy applies to this manifest
    pub fn applies_to(&self, manifest: &K8sManifest) -> bool {
        // Apply policies based on resource type
        match self.id.as_str() {
            id if id.starts_with("k8s-") => manifest.is_workload(),
            _ => true,
        }
    }

    /// Evaluate policy against manifest
    pub fn evaluate(
        &self,
        manifest: &K8sManifest,
        file_path: &Path,
        manifest_index: usize,
    ) -> Result<Option<Misconfiguration>> {
        (self.evaluator)(manifest).map(|opt| {
            opt.map(|mut misconfig| {
                misconfig.file_path = file_path.to_string_lossy().to_string();
                misconfig.line_range = Some((manifest_index * 100, manifest_index * 100 + 50)); // Approximate
                misconfig
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k8s_manifest_parsing() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test
    image: nginx
"#;

        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let manifest = K8sManifest::from_yaml_value(value).unwrap();

        assert_eq!(manifest.kind, "Pod");
        assert_eq!(manifest.metadata.name, "test-pod");
        assert!(manifest.is_workload());
    }

    #[test]
    fn test_k8s_policy_evaluation() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
"#;

        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let manifest = K8sManifest::from_yaml_value(value).unwrap();

        let policies = K8sDetector::get_builtin_k8s_policies();
        let privileged_policy = policies.iter().find(|p| p.id == "k8s-privileged-container").unwrap();

        assert!(privileged_policy.applies_to(&manifest));

        let result = privileged_policy.evaluate(&manifest, Path::new("test.yaml"), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_k8s_manifest() {
        let detector = K8sDetector {
            policies: Vec::new(),
        };

        assert!(detector.is_k8s_manifest(Path::new("deployment.yaml")));
        assert!(detector.is_k8s_manifest(Path::new("service.yml")));
        assert!(!detector.is_k8s_manifest(Path::new("Dockerfile")));
        assert!(!detector.is_k8s_manifest(Path::new("package.json")));
    }
}
