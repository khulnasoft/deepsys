use anyhow::Result;
use std::path::Path;

/// Utility functions for file operations
pub mod fs {
    use super::*;

    /// Check if a path exists and is readable
    pub fn path_exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    /// Get file size in bytes
    pub fn file_size(path: &str) -> Result<u64> {
        let metadata = std::fs::metadata(path)?;
        Ok(metadata.len())
    }

    /// Read file content as string
    pub fn read_file(path: &str) -> Result<String> {
        Ok(std::fs::read_to_string(path)?)
    }

    /// Walk directory recursively
    pub fn walk_dir(dir: &str) -> Result<Vec<String>> {
        let mut files = Vec::new();
        walk_dir_recursive(dir, &mut files)?;
        Ok(files)
    }

    fn walk_dir_recursive(dir: &str, files: &mut Vec<String>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                walk_dir_recursive(&path.to_string_lossy(), files)?;
            } else {
                files.push(path.to_string_lossy().to_string());
            }
        }
        Ok(())
    }
}

/// Utility functions for string operations
pub mod string {
    /// Check if string contains any of the patterns
    pub fn contains_any(s: &str, patterns: &[&str]) -> bool {
        patterns.iter().any(|pattern| s.contains(pattern))
    }

    /// Normalize whitespace in string
    pub fn normalize_whitespace(s: &str) -> String {
        s.split_whitespace().collect::<Vec<&str>>().join(" ")
    }

    /// Extract domain from URL
    pub fn extract_domain(url: &str) -> Option<&str> {
        url.strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .and_then(|s| s.split('/').next())
    }
}

/// Utility functions for version comparison
pub mod version {
    /// Compare two version strings
    pub fn compare_versions(v1: &str, v2: &str) -> std::cmp::Ordering {
        // Simple version comparison - in production, use semver crate
        let v1_parts: Vec<&str> = v1.split('.').collect();
        let v2_parts: Vec<&str> = v2.split('.').collect();

        for i in 0..std::cmp::max(v1_parts.len(), v2_parts.len()) {
            let part1 = v1_parts.get(i).unwrap_or(&"0").parse::<u32>().unwrap_or(0);
            let part2 = v2_parts.get(i).unwrap_or(&"0").parse::<u32>().unwrap_or(0);

            match part1.cmp(&part2) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Check if version satisfies requirement
    pub fn satisfies_requirement(version: &str, requirement: &str) -> bool {
        // Placeholder implementation
        version == requirement
    }
}

/// Utility functions for async operations
pub mod async_utils {
    use anyhow::Result;

    /// Retry an async operation with exponential backoff
    pub async fn retry_with_backoff<F, Fut, T>(
        mut operation: F,
        max_attempts: u32,
        base_delay_ms: u64,
    ) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        let mut delay = base_delay_ms;

        loop {
            attempt += 1;

            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) if attempt < max_attempts => {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    delay *= 2; // Exponential backoff
                }
                Err(e) => return Err(e),
            }
        }
    }
}
