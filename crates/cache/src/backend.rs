//! # Cache Backends
//!
//! Implementation of different cache storage backends including memory,
//! disk, and hybrid storage solutions.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, warn};

use crate::{Cache, CacheConfig, CacheEntry, CacheStats};

/// Disk-based cache implementation using sled
pub struct DiskCache {
    db: sled::Db,
    config: CacheConfig,
}

impl DiskCache {
    /// Create a new disk cache
    pub async fn new(config: &CacheConfig) -> Result<Self> {
        debug!("Initializing disk cache at: {:?}", config.cache_dir);

        // Create cache directory if it doesn't exist
        std::fs::create_dir_all(&config.cache_dir)?;

        // Open sled database
        let db = sled::open(&config.cache_dir)?;

        Ok(Self {
            db,
            config: config.clone(),
        })
    }
}

#[async_trait]
impl Cache for DiskCache {
    async fn get<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de> + Send,
    {
        match self.db.get(key.as_bytes())? {
            Some(data) => {
                // Deserialize cache entry
                let entry: CacheEntry<serde_json::Value> = serde_json::from_slice(&data)?;

                if !entry.is_expired() {
                    Ok(serde_json::from_value(entry.data).ok())
                } else {
                    // Entry expired, remove it
                    self.db.remove(key.as_bytes())?;
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn put<T>(&self, key: &str, value: T, ttl: Option<Duration>) -> Result<()>
    where
        T: Serialize + Send,
    {
        let serialized = serde_json::to_vec(&value)?;
        let size_bytes = serialized.len() as u64;

        // Check size limits
        if self.config.max_size_bytes > 0 && size_bytes > self.config.max_size_bytes {
            return Err(anyhow::anyhow!("Cache entry too large: {} bytes", size_bytes));
        }

        // Check entry limits
        if self.config.max_entries > 0 && self.db.len() >= self.config.max_entries {
            self.evict_entries().await?;
        }

        let ttl = ttl.unwrap_or(self.config.default_ttl);
        let entry = CacheEntry::new(value, key.to_string(), "disk".to_string())
            .with_ttl(ttl);

        let entry_data = serde_json::to_vec(&entry)?;
        self.db.insert(key.as_bytes(), entry_data)?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        Ok(self.db.remove(key.as_bytes())?.is_some())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        match self.db.get(key.as_bytes())? {
            Some(data) => {
                let entry: CacheEntry<serde_json::Value> = serde_json::from_slice(&data)?;
                Ok(!entry.is_expired())
            }
            None => Ok(false),
        }
    }

    async fn clear(&self) -> Result<()> {
        self.db.clear()?;
        Ok(())
    }

    async fn stats(&self) -> Result<CacheStats> {
        let total_entries = self.db.len();
        let total_size_bytes = total_entries as u64 * 1024; // Rough estimate

        Ok(CacheStats {
            total_entries,
            total_size_bytes,
            hits: 0, // Would need more sophisticated tracking
            misses: 0,
            hit_rate: 0.0,
            evictions: 0,
            avg_response_time_ms: 0.0,
            last_cleanup: None,
        })
    }

    async fn cleanup(&self) -> Result<usize> {
        let mut removed = 0;
        let mut keys_to_remove = Vec::new();

        // Find expired entries
        for item in self.db.iter() {
            let (key, data) = item?;
            if let Ok(entry) = serde_json::from_slice::<CacheEntry<serde_json::Value>>(&data) {
                if entry.is_expired() {
                    keys_to_remove.push(key.to_vec());
                }
            }
        }

        // Remove expired entries
        for key in keys_to_remove {
            self.db.remove(&key)?;
            removed += 1;
        }

        debug!("Removed {} expired entries from disk cache", removed);
        Ok(removed)
    }

    /// Evict entries based on LRU policy
    async fn evict_entries(&self) -> Result<()> {
        // Simple eviction: remove oldest entries
        let mut entries = Vec::new();

        for item in self.db.iter() {
            let (_, data) = item?;
            if let Ok(entry) = serde_json::from_slice::<CacheEntry<serde_json::Value>>(&data) {
                entries.push(entry);
            }
        }

        entries.sort_by_key(|entry| entry.accessed_at);

        let to_remove = (entries.len() / 4).max(10);

        for entry in entries.iter().take(to_remove) {
            self.db.remove(entry.key.as_bytes())?;
        }

        debug!("Evicted {} entries from disk cache", to_remove);
        Ok(())
    }
}

/// Memory-based cache implementation using DashMap
pub struct MemoryCache {
    cache: dashmap::DashMap<String, CacheEntry<serde_json::Value>>,
    config: CacheConfig,
}

impl MemoryCache {
    /// Create a new memory cache
    pub fn new(config: CacheConfig) -> Self {
        Self {
            cache: dashmap::DashMap::new(),
            config,
        }
    }
}

#[async_trait]
impl Cache for MemoryCache {
    async fn get<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de> + Send,
    {
        if let Some(mut entry) = self.cache.get_mut(key) {
            if !entry.is_expired() {
                entry.mark_accessed();
                return Ok(serde_json::from_value(entry.data.clone()).ok());
            } else {
                // Entry expired, remove it
                self.cache.remove(key);
            }
        }

        Ok(None)
    }

    async fn put<T>(&self, key: &str, value: T, ttl: Option<Duration>) -> Result<()>
    where
        T: Serialize + Send,
    {
        let serialized = serde_json::to_vec(&value)?;
        let size_bytes = serialized.len() as u64;

        // Check size limits
        if self.config.max_size_bytes > 0 && size_bytes > self.config.max_size_bytes {
            return Err(anyhow::anyhow!("Cache entry too large: {} bytes", size_bytes));
        }

        // Check entry limits
        if self.config.max_entries > 0 && self.cache.len() >= self.config.max_entries {
            self.evict_entries().await?;
        }

        let ttl = ttl.unwrap_or(self.config.default_ttl);
        let entry = CacheEntry::new(value, key.to_string(), "memory".to_string())
            .with_ttl(ttl);

        self.cache.insert(key.to_string(), entry);

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        Ok(self.cache.remove(key).is_some())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        if let Some(entry) = self.cache.get(key) {
            Ok(!entry.is_expired())
        } else {
            Ok(false)
        }
    }

    async fn clear(&self) -> Result<()> {
        self.cache.clear();
        Ok(())
    }

    async fn stats(&self) -> Result<CacheStats> {
        let total_entries = self.cache.len();
        let total_size_bytes = self.cache.iter().map(|entry| entry.size_bytes).sum();

        Ok(CacheStats {
            total_entries,
            total_size_bytes,
            hits: 0,
            misses: 0,
            hit_rate: 0.0,
            evictions: 0,
            avg_response_time_ms: 0.0,
            last_cleanup: None,
        })
    }

    async fn cleanup(&self) -> Result<usize> {
        let mut removed = 0;
        let initial_count = self.cache.len();

        self.cache.retain(|_, entry| {
            if entry.is_expired() {
                removed += 1;
                false
            } else {
                true
            }
        });

        debug!("Removed {} expired entries from memory cache", removed);
        Ok(removed)
    }

    /// Evict entries based on LRU policy
    async fn evict_entries(&self) -> Result<()> {
        let mut entries: Vec<_> = self.cache.iter().map(|entry| entry.clone()).collect();
        entries.sort_by_key(|entry| entry.accessed_at);

        let to_remove = (entries.len() / 4).max(10);

        for entry in entries.iter().take(to_remove) {
            self.cache.remove(&entry.key);
        }

        debug!("Evicted {} entries from memory cache", to_remove);
        Ok(())
    }
}

/// Cache backend factory
pub struct CacheFactory;

impl CacheFactory {
    /// Create cache instance based on configuration
    pub async fn create_cache(config: CacheConfig) -> Result<Box<dyn Cache>> {
        match config.backend {
            crate::CacheBackend::Memory => {
                Ok(Box::new(MemoryCache::new(config)))
            }
            crate::CacheBackend::Disk => {
                Ok(Box::new(DiskCache::new(&config).await?))
            }
            crate::CacheBackend::Hybrid => {
                // For hybrid, we'll use the HybridCache implementation from lib.rs
                Ok(Box::new(crate::HybridCache::new(config).await?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_cache_creation() {
        let config = CacheConfig::default();
        let cache = MemoryCache::new(config);

        assert!(cache.cache.is_empty());
    }

    #[tokio::test]
    async fn test_disk_cache_creation() {
        let config = CacheConfig {
            cache_dir: std::path::PathBuf::from("/tmp/test-cache"),
            backend: crate::CacheBackend::Disk,
            ..Default::default()
        };

        let cache = DiskCache::new(&config).await;
        assert!(cache.is_ok());
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let config = CacheConfig::default();
        let cache = MemoryCache::new(config);

        // Test put and get
        cache.put("test-key", "test-value", None).await.unwrap();
        let result: Option<String> = cache.get("test-key").await.unwrap();

        assert_eq!(result, Some("test-value".to_string()));

        // Test delete
        let deleted = cache.delete("test-key").await.unwrap();
        assert!(deleted);

        // Test exists
        let exists = cache.exists("test-key").await.unwrap();
        assert!(!exists);
    }
}
