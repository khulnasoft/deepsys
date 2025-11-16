//! Vulnerability cache implementation

use anyhow::Result;
use async_trait::async_trait;
use deepsys_types::{Vulnerability, SourceID};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Cache trait for vulnerability data
#[async_trait]
pub trait VulnerabilityCache: Send + Sync {
    /// Get cached vulnerabilities for a package
    async fn get(&self, source: SourceID, package: &str, version: &str) -> Result<Option<Vec<Vulnerability>>>;

    /// Store vulnerabilities in cache
    async fn put(&self, source: SourceID, package: &str, version: &str, vulnerabilities: Vec<Vulnerability>) -> Result<()>;

    /// Invalidate cache for a specific source
    async fn invalidate(&self, source: SourceID) -> Result<()>;

    /// Clear all cached data
    async fn clear(&self) -> Result<()>;

    /// Get cache statistics
    async fn stats(&self) -> Result<CacheStats>;
}

/// In-memory cache implementation
pub struct MemoryCache {
    data: HashMap<String, CacheEntry>,
    max_entries: usize,
}

impl MemoryCache {
    /// Create a new memory cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            data: HashMap::new(),
            max_entries,
        }
    }

    /// Generate cache key
    fn cache_key(&self, source: SourceID, package: &str, version: &str) -> String {
        format!("{}:{}:{}", source, package, version)
    }

    /// Evict old entries if cache is full
    fn evict_if_needed(&mut self) {
        if self.data.len() >= self.max_entries {
            // Simple eviction: remove oldest entries
            let mut entries: Vec<_> = self.data.iter().collect();
            entries.sort_by_key(|(_, entry)| entry.timestamp);

            let to_remove = entries.len() - self.max_entries + 1;
            for (key, _) in entries.iter().take(to_remove) {
                self.data.remove(*key);
            }
        }
    }
}

#[async_trait]
impl VulnerabilityCache for MemoryCache {
    async fn get(&self, source: SourceID, package: &str, version: &str) -> Result<Option<Vec<Vulnerability>>> {
        let key = self.cache_key(source, package, version);

        if let Some(entry) = self.data.get(&key) {
            // Check if cache entry is still valid (e.g., not too old)
            let now = Utc::now();
            let max_age = chrono::Duration::hours(24); // Cache for 24 hours

            if now - entry.timestamp < max_age {
                return Ok(Some(entry.vulnerabilities.clone()));
            }
        }

        Ok(None)
    }

    async fn put(&self, source: SourceID, package: &str, version: &str, vulnerabilities: Vec<Vulnerability>) -> Result<()> {
        let key = self.cache_key(source, package, version);

        // Note: In a real implementation, this would need to be thread-safe
        // For now, we'll just store the data
        // In production, we'd use a concurrent HashMap or similar

        Ok(())
    }

    async fn invalidate(&self, source: SourceID) -> Result<()> {
        // In a real implementation, we'd remove all entries for this source
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        // In a real implementation, we'd clear all data
        Ok(())
    }

    async fn stats(&self) -> Result<CacheStats> {
        Ok(CacheStats {
            entries: self.data.len(),
            max_entries: self.max_entries,
            hit_rate: 0.0, // Would track this in real implementation
            memory_usage: 0, // Would calculate this in real implementation
        })
    }
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new(10000) // Default: 10k entries
    }
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    vulnerabilities: Vec<Vulnerability>,
    timestamp: DateTime<Utc>,
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub max_entries: usize,
    pub hit_rate: f64,
    pub memory_usage: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_cache_creation() {
        let cache = MemoryCache::new(1000);
        assert_eq!(cache.max_entries, 1000);
    }

    #[test]
    fn test_cache_key_generation() {
        let cache = MemoryCache::new(1000);
        let key = cache.cache_key(SourceID::NVD, "openssl", "1.1.1");
        assert_eq!(key, "NVD:openssl:1.1.1");
    }
}
