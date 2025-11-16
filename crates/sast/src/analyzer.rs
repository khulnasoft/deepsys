//! # Analyzers
//!
//! Core analyzer types and traits for artifact analysis.

use anyhow::Result;
use async_trait::async_trait;
use deepsys_types::{Package, PackageIdentifier, OS, Application};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalyzerType {
    OS,
    Package,
    Language,
    Secret,
    Kubernetes,
    Misconfiguration,
}

#[async_trait]
pub trait Analyzer: Send + Sync {
    fn analyzer_type(&self) -> AnalyzerType;
    async fn analyze(&self, path: &std::path::Path) -> Result<AnalysisResult>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub os: Option<OS>,
    pub packages: Vec<Package>,
    pub applications: Vec<Application>,
    pub dependencies: Vec<PackageIdentifier>,
    pub custom_data: HashMap<String, String>,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self {
            os: None,
            packages: Vec::new(),
            applications: Vec::new(),
            dependencies: Vec::new(),
            custom_data: HashMap::new(),
        }
    }
}

pub struct OsAnalyzer;

impl OsAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Analyzer for OsAnalyzer {
    fn analyzer_type(&self) -> AnalyzerType {
        AnalyzerType::OS
    }

    async fn analyze(&self, _path: &std::path::Path) -> Result<AnalysisResult> {
        Ok(AnalysisResult::default())
    }
}

pub struct PackageAnalyzer;

impl PackageAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Analyzer for PackageAnalyzer {
    fn analyzer_type(&self) -> AnalyzerType {
        AnalyzerType::Package
    }

    async fn analyze(&self, _path: &std::path::Path) -> Result<AnalysisResult> {
        Ok(AnalysisResult::default())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AnalyzerGroup {
    analyzers: HashMap<AnalyzerType, Vec<Box<dyn Analyzer>>>,
}

impl AnalyzerGroup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        let analyzer_type = analyzer.analyzer_type();
        self.analyzers.entry(analyzer_type).or_insert_with(Vec::new).push(analyzer);
    }
}

pub mod groups {
    use super::*;

    pub fn image_analyzers() -> AnalyzerGroup {
        let mut group = AnalyzerGroup::new();
        group.add_analyzer(Box::new(OsAnalyzer::new()));
        group.add_analyzer(Box::new(PackageAnalyzer::new()));
        group
    }

    pub fn filesystem_analyzers() -> AnalyzerGroup {
        let mut group = AnalyzerGroup::new();
        group.add_analyzer(Box::new(OsAnalyzer::new()));
        group.add_analyzer(Box::new(PackageAnalyzer::new()));
        group
    }

    pub fn kubernetes_analyzers() -> AnalyzerGroup {
        let mut group = AnalyzerGroup::new();
        group.add_analyzer(Box::new(OsAnalyzer::new()));
        group
    }
}
