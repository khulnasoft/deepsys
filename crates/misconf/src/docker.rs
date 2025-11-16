//! # Docker Misconfiguration Detector
//!
//! Specialized detector for Docker files and configurations.
//! Identifies security misconfigurations and best practice violations
//! in Dockerfiles and docker-compose files.

use anyhow::Result;
use deepsys_types::{Misconfiguration, SecurityIssue, Severity};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

use crate::{Policy, MisconfConfig};

/// Docker detector for Dockerfile analysis
pub struct DockerDetector {
    policies: Vec<DockerPolicy>,
}

impl DockerDetector {
    /// Create a new Docker detector
    pub async fn new() -> Result<Self> {
        let policies = Self::get_builtin_docker_policies();

        Ok(Self { policies })
    }

    /// Scan filesystem for Docker files
    pub async fn scan_filesystem(&self, root_path: &str) -> Result<Vec<SecurityIssue>> {
        let mut misconfigs = Vec::new();

        for entry in walkdir::WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();

                if self.is_docker_file(file_path) {
                    if let Ok(file_misconfigs) = self.scan_docker_file(file_path).await {
                        misconfigs.extend(file_misconfigs);
                    }
                }
            }
        }

        Ok(misconfigs)
    }

    /// Scan a single Docker file
    async fn scan_docker_file(&self, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let content = tokio::fs::read_to_string(file_path).await?;

        if self.is_dockerfile(file_path) {
            self.scan_dockerfile(&content, file_path).await
        } else if self.is_docker_compose(file_path) {
            self.scan_docker_compose(&content, file_path).await
        } else {
            Ok(Vec::new())
        }
    }

    /// Scan Dockerfile content
    async fn scan_dockerfile(&self, content: &str, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let instructions = self.parse_dockerfile(content)?;
        let mut misconfigs = Vec::new();

        for (line_num, instruction) in instructions.iter().enumerate() {
            for policy in &self.policies {
                if policy.applies_to_instruction(instruction) {
                    if let Some(misconfig) = policy.evaluate(instruction, file_path, line_num + 1)? {
                        misconfigs.push(SecurityIssue::Misconfiguration(misconfig));
                    }
                }
            }
        }

        Ok(misconfigs)
    }

    /// Scan docker-compose content
    async fn scan_docker_compose(&self, content: &str, file_path: &Path) -> Result<Vec<SecurityIssue>> {
        let compose = serde_yaml::from_str::<serde_yaml::Value>(content)
            .map_err(|e| anyhow::anyhow!("Failed to parse docker-compose: {}", e))?;

        let mut misconfigs = Vec::new();

        // Apply docker-compose specific policies
        for policy in &self.policies {
            if policy.is_compose_policy() {
                if let Some(misconfig) = policy.evaluate_compose(&compose, file_path)? {
                    misconfigs.push(SecurityIssue::Misconfiguration(misconfig));
                }
            }
        }

        Ok(misconfigs)
    }

    /// Parse Dockerfile instructions
    fn parse_dockerfile(&self, content: &str) -> Result<Vec<DockerInstruction>> {
        let mut instructions = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(instruction) = DockerInstruction::parse(line, line_num + 1) {
                instructions.push(instruction);
            }
        }

        Ok(instructions)
    }

    /// Check if file is a Docker file
    fn is_docker_file(&self, file_path: &Path) -> bool {
        self.is_dockerfile(file_path) || self.is_docker_compose(file_path)
    }

    /// Check if file is a Dockerfile
    fn is_dockerfile(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        filename.to_lowercase().starts_with("dockerfile")
    }

    /// Check if file is a docker-compose file
    fn is_docker_compose(&self, file_path: &Path) -> bool {
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        filename.to_lowercase().starts_with("docker-compose")
    }

    /// Get built-in Docker security policies
    fn get_builtin_docker_policies() -> Vec<DockerPolicy> {
        vec![
            DockerPolicy::new(
                "docker-root-user".to_string(),
                "Root User".to_string(),
                Severity::High,
                "Running containers as root user poses security risks".to_string(),
                Box::new(|instruction: &DockerInstruction| -> Result<Option<Misconfiguration>> {
                    if instruction.command.to_uppercase() == "USER" {
                        if instruction.arguments.iter().any(|arg| arg == "root" || arg == "0") {
                            return Ok(Some(Misconfiguration {
                                id: "docker-root-user".to_string(),
                                title: "Root User".to_string(),
                                description: "Container is configured to run as root user".to_string(),
                                severity: Severity::High,
                                resolution: "Use a non-root user in Docker containers".to_string(),
                                references: vec!["https://docs.docker.com/develop/dev-best-practices/".to_string()],
                                file_path: "".to_string(),
                                line_range: Some((instruction.line_number, instruction.line_number)),
                                resource_type: Some("Dockerfile".to_string()),
                                resource_name: None,
                                custom_fields: HashMap::new(),
                            }));
                        }
                    }
                    Ok(None)
                }),
            ),
            DockerPolicy::new(
                "docker-latest-tag".to_string(),
                "Latest Tag Usage".to_string(),
                Severity::Medium,
                "Using latest tags makes images non-reproducible".to_string(),
                Box::new(|instruction: &DockerInstruction| -> Result<Option<Misconfiguration>> {
                    if instruction.command.to_uppercase() == "FROM" {
                        if instruction.arguments.iter().any(|arg| arg.ends_with(":latest")) {
                            return Ok(Some(Misconfiguration {
                                id: "docker-latest-tag".to_string(),
                                title: "Latest Tag Usage".to_string(),
                                description: "Image uses latest tag which is not reproducible".to_string(),
                                severity: Severity::Medium,
                                resolution: "Use specific version tags instead of latest".to_string(),
                                references: vec!["https://docs.docker.com/develop/dev-best-practices/".to_string()],
                                file_path: "".to_string(),
                                line_range: Some((instruction.line_number, instruction.line_number)),
                                resource_type: Some("Dockerfile".to_string()),
                                resource_name: None,
                                custom_fields: HashMap::new(),
                            }));
                        }
                    }
                    Ok(None)
                }),
            ),
            DockerPolicy::new(
                "docker-healthcheck".to_string(),
                "Missing Health Check".to_string(),
                Severity::Low,
                "Health checks help ensure container reliability".to_string(),
                Box::new(|instruction: &DockerInstruction| -> Result<Option<Misconfiguration>> {
                    // Check if there's a HEALTHCHECK instruction
                    if instruction.command.to_uppercase() == "HEALTHCHECK" {
                        return Ok(None); // Health check is present
                    }

                    // Check if this is the last instruction (simple heuristic)
                    // In a real implementation, you'd parse the entire Dockerfile structure
                    Ok(Some(Misconfiguration {
                        id: "docker-healthcheck".to_string(),
                        title: "Missing Health Check".to_string(),
                        description: "Dockerfile does not have a HEALTHCHECK instruction".to_string(),
                        severity: Severity::Low,
                        resolution: "Add HEALTHCHECK instruction to Dockerfile".to_string(),
                        references: vec!["https://docs.docker.com/engine/reference/builder/#healthcheck".to_string()],
                        file_path: "".to_string(),
                        line_range: None,
                        resource_type: Some("Dockerfile".to_string()),
                        resource_name: None,
                        custom_fields: HashMap::new(),
                    }))
                }),
            ),
            DockerPolicy::new_compose(
                "docker-compose-privileged".to_string(),
                "Privileged Mode in Compose".to_string(),
                Severity::High,
                "Privileged mode in docker-compose is dangerous".to_string(),
                Box::new(|compose: &serde_yaml::Value, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    // Check services for privileged mode
                    if let Some(services) = compose.get("services") {
                        if let Some(services_map) = services.as_mapping() {
                            for (service_name, service_config) in services_map {
                                if let Some(service_map) = service_config.as_mapping() {
                                    if let Some(privileged) = service_map.get("privileged") {
                                        if privileged.as_bool().unwrap_or(false) {
                                            return Ok(Some(Misconfiguration {
                                                id: "docker-compose-privileged".to_string(),
                                                title: "Privileged Mode in Compose".to_string(),
                                                description: format!("Service '{}' is running in privileged mode", service_name.as_str().unwrap_or("unknown")),
                                                severity: Severity::High,
                                                resolution: "Remove privileged mode from docker-compose service".to_string(),
                                                references: vec!["https://docs.docker.com/compose/compose-file/".to_string()],
                                                file_path: file_path.to_string_lossy().to_string(),
                                                line_range: None,
                                                resource_type: Some("docker-compose".to_string()),
                                                resource_name: service_name.as_str().map(|s| s.to_string()),
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
            DockerPolicy::new_compose(
                "docker-compose-network-mode".to_string(),
                "Host Network Mode".to_string(),
                Severity::Medium,
                "Host network mode can expose all host ports".to_string(),
                Box::new(|compose: &serde_yaml::Value, file_path: &Path| -> Result<Option<Misconfiguration>> {
                    if let Some(services) = compose.get("services") {
                        if let Some(services_map) = services.as_mapping() {
                            for (service_name, service_config) in services_map {
                                if let Some(service_map) = service_config.as_mapping() {
                                    if let Some(network_mode) = service_map.get("network_mode") {
                                        if network_mode.as_str().unwrap_or("") == "host" {
                                            return Ok(Some(Misconfiguration {
                                                id: "docker-compose-network-mode".to_string(),
                                                title: "Host Network Mode".to_string(),
                                                description: format!("Service '{}' uses host network mode", service_name.as_str().unwrap_or("unknown")),
                                                severity: Severity::Medium,
                                                resolution: "Avoid using host network mode in production".to_string(),
                                                references: vec!["https://docs.docker.com/compose/compose-file/".to_string()],
                                                file_path: file_path.to_string_lossy().to_string(),
                                                line_range: None,
                                                resource_type: Some("docker-compose".to_string()),
                                                resource_name: service_name.as_str().map(|s| s.to_string()),
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
        ]
    }
}

/// Docker instruction representation
#[derive(Debug, Clone)]
pub struct DockerInstruction {
    pub command: String,
    pub arguments: Vec<String>,
    pub line_number: usize,
    pub original_line: String,
}

impl DockerInstruction {
    /// Parse a Dockerfile line into an instruction
    pub fn parse(line: &str, line_number: usize) -> Option<Self> {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        // Find the first space or tab
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let command = parts[0].to_uppercase();
        let arguments: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        Some(Self {
            command,
            arguments,
            line_number,
            original_line: line.to_string(),
        })
    }

    /// Check if instruction is a FROM instruction
    pub fn is_from(&self) -> bool {
        self.command == "FROM"
    }

    /// Check if instruction is a USER instruction
    pub fn is_user(&self) -> bool {
        self.command == "USER"
    }

    /// Check if instruction is a RUN instruction
    pub fn is_run(&self) -> bool {
        self.command == "RUN"
    }

    /// Check if instruction is a COPY instruction
    pub fn is_copy(&self) -> bool {
        self.command == "COPY"
    }

    /// Check if instruction is an ADD instruction
    pub fn is_add(&self) -> bool {
        self.command == "ADD"
    }
}

/// Docker-specific policy
pub struct DockerPolicy {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub instruction_evaluator: Option<Box<dyn Fn(&DockerInstruction) -> Result<Option<Misconfiguration>> + Send + Sync>>,
    pub compose_evaluator: Option<Box<dyn Fn(&serde_yaml::Value, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>>,
}

impl DockerPolicy {
    /// Create a new Dockerfile policy
    pub fn new(
        id: String,
        title: String,
        severity: Severity,
        description: String,
        evaluator: Box<dyn Fn(&DockerInstruction) -> Result<Option<Misconfiguration>> + Send + Sync>,
    ) -> Self {
        Self {
            id,
            title,
            severity,
            description,
            instruction_evaluator: Some(evaluator),
            compose_evaluator: None,
        }
    }

    /// Create a new docker-compose policy
    pub fn new_compose(
        id: String,
        title: String,
        severity: Severity,
        description: String,
        evaluator: Box<dyn Fn(&serde_yaml::Value, &Path) -> Result<Option<Misconfiguration>> + Send + Sync>,
    ) -> Self {
        Self {
            id,
            title,
            severity,
            description,
            instruction_evaluator: None,
            compose_evaluator: Some(evaluator),
        }
    }

    /// Check if policy applies to this instruction
    pub fn applies_to_instruction(&self, instruction: &DockerInstruction) -> bool {
        match self.id.as_str() {
            "docker-root-user" => instruction.is_user(),
            "docker-latest-tag" => instruction.is_from(),
            "docker-healthcheck" => true, // Applies to entire file
            _ => true,
        }
    }

    /// Check if this is a compose policy
    pub fn is_compose_policy(&self) -> bool {
        self.compose_evaluator.is_some()
    }

    /// Evaluate policy against Dockerfile instruction
    pub fn evaluate(
        &self,
        instruction: &DockerInstruction,
        file_path: &Path,
        line_number: usize,
    ) -> Result<Option<Misconfiguration>> {
        if let Some(ref evaluator) = self.instruction_evaluator {
            evaluator(instruction).map(|opt| {
                opt.map(|mut misconfig| {
                    misconfig.file_path = file_path.to_string_lossy().to_string();
                    misconfig.line_range = Some((line_number, line_number));
                    misconfig
                })
            })
        } else {
            Ok(None)
        }
    }

    /// Evaluate policy against docker-compose
    pub fn evaluate_compose(
        &self,
        compose: &serde_yaml::Value,
        file_path: &Path,
    ) -> Result<Option<Misconfiguration>> {
        if let Some(ref evaluator) = self.compose_evaluator {
            evaluator(compose, file_path)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dockerfile_parsing() {
        let detector = DockerDetector {
            policies: Vec::new(),
        };

        let dockerfile = r#"
FROM ubuntu:20.04
RUN apt-get update
USER root
COPY . /app
"#;

        let instructions = detector.parse_dockerfile(dockerfile).unwrap();

        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].command, "FROM");
        assert_eq!(instructions[1].command, "RUN");
        assert_eq!(instructions[2].command, "USER");
        assert_eq!(instructions[3].command, "COPY");
    }

    #[test]
    fn test_docker_instruction_parsing() {
        let instruction = DockerInstruction::parse("FROM ubuntu:20.04", 1).unwrap();
        assert_eq!(instruction.command, "FROM");
        assert_eq!(instruction.arguments, vec!["ubuntu:20.04"]);

        let user_instruction = DockerInstruction::parse("USER appuser", 2).unwrap();
        assert_eq!(user_instruction.command, "USER");
        assert_eq!(user_instruction.arguments, vec!["appuser"]);
    }

    #[test]
    fn test_is_docker_file() {
        let detector = DockerDetector {
            policies: Vec::new(),
        };

        assert!(detector.is_dockerfile(Path::new("Dockerfile")));
        assert!(detector.is_dockerfile(Path::new("Dockerfile.prod")));
        assert!(detector.is_docker_compose(Path::new("docker-compose.yml")));
        assert!(detector.is_docker_compose(Path::new("docker-compose.override.yml")));
        assert!(!detector.is_docker_file(Path::new("README.md")));
    }

    #[test]
    fn test_docker_compose_parsing() {
        let yaml = r#"
version: '3.8'
services:
  web:
    image: nginx
    privileged: true
  db:
    image: postgres
    network_mode: host
"#;

        let compose: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();

        // Test privileged service detection
        if let Some(services) = compose.get("services") {
            if let Some(services_map) = services.as_mapping() {
                if let Some(web_service) = services_map.get(&serde_yaml::Value::String("web".to_string())) {
                    if let Some(service_map) = web_service.as_mapping() {
                        assert!(service_map.get("privileged").unwrap().as_bool().unwrap());
                    }
                }
            }
        }
    }
}
