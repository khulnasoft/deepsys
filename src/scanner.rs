use crate::{Scanner, ScanResult, ScanTarget};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// Scanner for container images
pub struct ImageScanner {
    scanner: Arc<dyn Scanner>,
}

impl ImageScanner {
    pub fn new(scanner: Arc<dyn Scanner>) -> Self {
        Self { scanner }
    }

    /// Scan a container image
    pub async fn scan_image(&self, image_name: String) -> Result<ScanResult> {
        let target = deepsys_types::ScanTarget::Image {
            name: image_name,
            registry: None,
            tag: None
        };
        self.scanner.scan(target).await
    }
}

/// Scanner for filesystem paths
pub struct FilesystemScanner {
    scanner: Arc<dyn Scanner>,
}

impl FilesystemScanner {
    pub fn new(scanner: Arc<dyn Scanner>) -> Self {
        Self { scanner }
    }

    /// Scan a filesystem path
    pub async fn scan_path(&self, path: String) -> Result<ScanResult> {
        let target = deepsys_types::ScanTarget::Filesystem {
            path,
            recursive: true
        };
        self.scanner.scan(target).await
    }
}

/// Scanner for Git repositories
pub struct GitScanner {
    scanner: Arc<dyn Scanner>,
}

impl GitScanner {
    pub fn new(scanner: Arc<dyn Scanner>) -> Self {
        Self { scanner }
    }

    /// Scan a Git repository
    pub async fn scan_repo(&self, url: String) -> Result<ScanResult> {
        let target = deepsys_types::ScanTarget::Repository {
            url,
            branch: None,
            commit: None
        };
        self.scanner.scan(target).await
    }
}

/// Scanner for Kubernetes manifests
pub struct KubernetesScanner {
    scanner: Arc<dyn Scanner>,
}

impl KubernetesScanner {
    pub fn new(scanner: Arc<dyn Scanner>) -> Self {
        Self { scanner }
    }

    /// Scan Kubernetes manifests
    pub async fn scan_k8s(&self, path: String) -> Result<ScanResult> {
        let target = deepsys_types::ScanTarget::Kubernetes {
            path,
            namespace: None
        };
        self.scanner.scan(target).await
    }
}
