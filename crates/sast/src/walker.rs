
//! # Walker
//!
//! Filesystem traversal utilities for artifact analysis. The walker module provides
//! efficient and configurable filesystem walking capabilities with filtering and
//! parallel processing support.

use anyhow::Result;
use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, trace};

use crate::types::{AnalysisContext, FileFilter, FileInfo, FileType};

/// Filesystem walker for traversing directories
pub struct Walker {
    filter: FileFilter,
    context: AnalysisContext,
}

impl Walker {
    /// Create a new walker with the given filter and context
    pub fn new(filter: FileFilter, context: AnalysisContext) -> Self {
        Self { filter, context }
    }

    /// Walk the filesystem and collect file information
    pub async fn walk(&self) -> Result<Vec<FileInfo>> {
        let mut files = Vec::new();
        self.walk_recursive(&self.context.root_path, &mut files, 0).await?;
        Ok(files)
    }

    /// Recursively walk directories
    async fn walk_recursive(
        &self,
        dir: &Path,
        files: &mut Vec<FileInfo>,
        depth: usize,
    ) -> Result<()> {
        // Check depth limit
        if self.filter.max_depth > 0 && depth >= self.filter.max_depth {
            return Ok(());
        }

        let mut entries = fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Check if path should be included
            if !self.filter.should_include(&path) {
                continue;
            }

            let metadata = entry.metadata().await?;

            if metadata.is_dir() {
                // Update directory count
                self.context.stats.directories_traversed += 1;

                // Recurse into subdirectory
                self.walk_recursive(&path, files, depth + 1).await?;
            } else if metadata.is_file() {
                // Process file
                let file_info = self.process_file(&path, &metadata).await?;
                files.push(file_info);

                // Update statistics
                self.context.stats.files_processed += 1;
                self.context.stats.bytes_processed += metadata.len();
            }
        }

        Ok(())
    }

    /// Process a single file and extract information
    async fn process_file(&self, path: &Path, metadata: &fs::Metadata) -> Result<FileInfo> {
        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_file() {
            FileType::Regular
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::Unknown
        };

        let permissions = if cfg!(unix) {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        } else {
            None
        };

        Ok(FileInfo {
            path: path.to_string_lossy().to_string(),
            size: metadata.len(),
            permissions,
            file_type,
            modified_at: metadata.modified().ok().map(|t| {
                chrono::DateTime::from_timestamp(t.as_secs() as i64, t.subsec_nanos())
                    .unwrap_or_else(chrono::Utc::now)
            }),
            md5_hash: None, // Will be calculated if needed
            sha256_hash: None, // Will be calculated if needed
            mime_type: self.detect_mime_type(path).await,
            extended_attrs: HashMap::new(),
        })
    }

    /// Detect MIME type for a file
    async fn detect_mime_type(&self, path: &Path) -> Option<String> {
        // Simple MIME type detection based on file extension
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| match ext {
                "json" => "application/json",
                "yaml" | "yml" => "application/yaml",
                "toml" => "application/toml",
                "xml" => "application/xml",
                "txt" => "text/plain",
                "md" => "text/markdown",
                "rs" => "text/x-rust",
                "py" => "text/x-python",
                "js" => "application/javascript",
                "ts" => "application/typescript",
                "go" => "text/x-go",
                "java" => "text/x-java",
                "c" => "text/x-c",
                "cpp" | "cc" | "cxx" => "text/x-c++",
                "h" | "hpp" => "text/x-c-header",
                "sh" => "application/x-shellscript",
                "html" => "text/html",
                "css" => "text/css",
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "gif" => "image/gif",
                "svg" => "image/svg+xml",
                "pdf" => "application/pdf",
                "zip" => "application/zip",
                "tar" => "application/x-tar",
                "gz" => "application/gzip",
                "bz2" => "application/x-bzip2",
                "xz" => "application/x-xz",
                _ => "application/octet-stream",
            })
            .map(|s| s.to_string())
    }
}

/// Parallel walker for high-performance filesystem traversal
pub struct ParallelWalker {
    filter: FileFilter,
    context: AnalysisContext,
    batch_config: crate::types::BatchConfig,
}

impl ParallelWalker {
    /// Create a new parallel walker
    pub fn new(filter: FileFilter, context: AnalysisContext, batch_config: crate::types::BatchConfig) -> Self {
        Self {
            filter,
            context,
            batch_config,
        }
    }

    /// Walk the filesystem in parallel and collect file information
    pub async fn walk_parallel(&self) -> Result<Vec<FileInfo>> {
        let start_time = std::time::Instant::now();

        // Collect all file paths first
        let all_paths = self.collect_paths().await?;

        // Process files in parallel batches
        let files = self.process_batches(all_paths).await?;

        // Update processing statistics
        self.context.stats.processing_time = start_time.elapsed();

        Ok(files)
    }

    /// Collect all file paths to process
    async fn collect_paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();

        // Use synchronous walker for path collection to avoid complexity
        for entry in walkdir::WalkDir::new(&self.context.root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !self.filter.should_include(path) {
                continue;
            }

            if entry.file_type().is_file() {
                paths.push(path.to_path_buf());
            }
        }

        debug!("Collected {} files for processing", paths.len());
        Ok(paths)
    }

    /// Process files in parallel batches
    async fn process_batches(&self, paths: Vec<PathBuf>) -> Result<Vec<FileInfo>> {
        let stream = stream::iter(paths)
            .map(|path| async move {
                self.process_single_file(&path).await
            })
            .buffer_unordered(self.batch_config.workers);

        let results: Vec<Result<FileInfo>> = stream.collect().await;
        let mut files = Vec::new();

        for result in results {
            match result {
                Ok(file_info) => files.push(file_info),
                Err(e) => {
                    self.context.add_error(format!("Failed to process file: {}", e));
                }
            }
        }

        Ok(files)
    }

    /// Process a single file
    async fn process_single_file(&self, path: &Path) -> Result<FileInfo> {
        let metadata = fs::metadata(path).await?;

        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_file() {
            FileType::Regular
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::Unknown
        };

        let permissions = if cfg!(unix) {
            use std::os::unix::fs::PermissionsExt;
            Some(metadata.permissions().mode())
        } else {
            None
        };

        Ok(FileInfo {
            path: path.to_string_lossy().to_string(),
            size: metadata.len(),
            permissions,
            file_type,
            modified_at: metadata.modified().ok().map(|t| {
                chrono::DateTime::from_timestamp(t.as_secs() as i64, t.subsec_nanos())
                    .unwrap_or_else(chrono::Utc::now)
            }),
            md5_hash: None,
            sha256_hash: None,
            mime_type: self.detect_mime_type(path).await,
            extended_attrs: HashMap::new(),
        })
    }

    /// Detect MIME type for a file
    async fn detect_mime_type(&self, path: &Path) -> Option<String> {
        // Simple MIME type detection based on file extension
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| match ext {
                "json" => "application/json",
                "yaml" | "yml" => "application/yaml",
                "toml" => "application/toml",
                "xml" => "application/xml",
                "txt" => "text/plain",
                "md" => "text/markdown",
                "rs" => "text/x-rust",
                "py" => "text/x-python",
                "js" => "application/javascript",
                "ts" => "application/typescript",
                "go" => "text/x-go",
                "java" => "text/x-java",
                "c" => "text/x-c",
                "cpp" | "cc" | "cxx" => "text/x-c++",
                "h" | "hpp" => "text/x-c-header",
                "sh" => "application/x-shellscript",
                "html" => "text/html",
                "css" => "text/css",
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "gif" => "image/gif",
                "svg" => "image/svg+xml",
                "pdf" => "application/pdf",
                "zip" => "application/zip",
                "tar" => "application/x-tar",
                "gz" => "application/gzip",
                "bz2" => "application/x-bzip2",
                "xz" => "application/x-xz",
                _ => "application/octet-stream",
            })
            .map(|s| s.to_string())
    }
}

/// Utility functions for filesystem operations
pub mod utils {
    use super::*;
    use std::collections::HashMap;

    /// Calculate MD5 hash of a file
    pub async fn calculate_md5(path: &Path) -> Result<String> {
        let data = fs::read(path).await?;
        Ok(format!("{:x}", md5::compute(&data)))
    }

    /// Calculate SHA256 hash of a file
    pub async fn calculate_sha256(path: &Path) -> Result<String> {
        let data = fs::read(path).await?;
        Ok(format!("{:x}", sha2::Sha256::digest(&data)))
    }

    /// Get file permissions as a string
    pub fn format_permissions(permissions: u32) -> String {
        let mut result = String::with_capacity(10);

        // File type
        let file_type = (permissions & 0o170000) >> 12;
        result.push(match file_type {
            0o10 => 'p', // Named pipe
            0o20 => 'c', // Character device
            0o40 => 'd', // Directory
            0o60 => 'b', // Block device
            0o100 => '-', // Regular file
            0o120 => 'l', // Symbolic link
            0o140 => 's', // Socket
            _ => '?',
        });

        // Owner permissions
        result.push(if permissions & 0o400 != 0 { 'r' } else { '-' });
        result.push(if permissions & 0o200 != 0 { 'w' } else { '-' });
        result.push(if permissions & 0o100 != 0 {
            if permissions & 0o4000 != 0 { 's' } else { 'x' }
        } else {
            if permissions & 0o4000 != 0 { 'S' } else { '-' }
        });

        // Group permissions
        result.push(if permissions & 0o040 != 0 { 'r' } else { '-' });
        result.push(if permissions & 0o020 != 0 { 'w' } else { '-' });
        result.push(if permissions & 0o010 != 0 {
            if permissions & 0o2000 != 0 { 's' } else { 'x' }
        } else {
            if permissions & 0o2000 != 0 { 'S' } else { '-' }
        });

        // Other permissions
        result.push(if permissions & 0o004 != 0 { 'r' } else { '-' });
        result.push(if permissions & 0o002 != 0 { 'w' } else { '-' });
        result.push(if permissions & 0o001 != 0 {
            if permissions & 0o1000 != 0 { 't' } else { 'x' }
        } else {
            if permissions & 0o1000 != 0 { 'T' } else { '-' }
        });

        result
    }

    /// Check if a path is a hidden file or directory
    pub fn is_hidden(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.starts_with('.'))
            .unwrap_or(false)
    }

    /// Get file extension
    pub fn get_extension(path: &Path) -> Option<String> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase())
    }

    /// Normalize path separators for cross-platform compatibility
    pub fn normalize_path(path: &str) -> String {
        path.replace('\\', "/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_filter_should_include_basic() {
        let filter = FileFilter::default();

        // Should exclude .git directory
        assert!(!filter.should_include(std::path::Path::new(".git/config")));
        // Should include regular files
        assert!(filter.should_include(std::path::Path::new("src/lib.rs")));
    }

    #[test]
    fn test_utils_format_permissions() {
        // Test regular file permissions (644)
        let permissions = format_permissions(0o100644);
        assert_eq!(permissions, "-rw-r--r--");
    }

    #[test]
    fn test_utils_is_hidden() {
        assert!(utils::is_hidden(std::path::Path::new(".hidden")));
        assert!(!utils::is_hidden(std::path::Path::new("visible")));
        assert!(!utils::is_hidden(std::path::Path::new("file.txt")));
    }

    #[test]
    fn test_utils_get_extension() {
        assert_eq!(utils::get_extension(std::path::Path::new("file.rs")), Some("rs".to_string()));
        assert_eq!(utils::get_extension(std::path::Path::new("file.RS")), Some("rs".to_string()));
        assert_eq!(utils::get_extension(std::path::Path::new("file")), None);
    }
}
