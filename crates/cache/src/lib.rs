//! # Caching System
//!
//! High-performance caching system for Deepsys security scanner. Provides
//! multiple caching backends including in-memory and persistent storage
//! for various types of data including scan results, vulnerability data,
//! and analysis artifacts.
//!
//! Features:
//! - Multiple cache backends (memory, disk)
//! - Configurable TTL and eviction policies
//! - Concurrent access with thread safety
//! - Cache key generation and management
//! - Performance metrics and monitoring

use anyhow::Result;
use async_trait::async_trait;
use deepsys_types::{ScanResult, ScanTarget};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

pub mod backend;
pub mod manager;
pub mod metrics;
pub mod policy;

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,

    /// Cache backend type
    pub backend: CacheBackend,

    /// Cache directory for persistent storage
    pub cache_dir: PathBuf,

    /// Default TTL for cache entries
    pub default_ttl: Duration,

    /// Maximum cache size in bytes (0 = unlimited)
    pub max_size_bytes: u64,

    /// Maximum number of entries (0 = unlimited)
    pub max_entries: usize,

    /// Enable cache compression
    pub enable_compression: bool,

    /// Enable cache encryption
    pub enable_encryption: bool,

    /// Cache cleanup interval
    pub cleanup_interval: Duration,

    /// Enable metrics collection
    pub enable_metrics: bool,

    /// Cache namespaces for organization
    pub namespaces: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: CacheBackend::Hybrid,
            cache_dir: PathBuf::from("./cache"),
            default_ttl: Duration::from_secs(3600), // 1 hour
            max_size_bytes: 100 * 1024 * 1024, // 100MB
            max_entries: 10000,
            enable_compression: true,
            enable_encryption: false,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            enable_metrics: true,
            namespaces: vec!["scan_results".to_string(), "vulnerabilities".to_string(), "artifacts".to_string()],
        }
    }
}

/// Cache backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheBackend {
    Memory,
    Disk,
    Hybrid,
}

/// Cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    /// Cached data
    pub data: T,

    /// Cache key
    pub key: String,

    /// Creation timestamp
    pub created_at: SystemTime,

    /// Last access timestamp
    pub accessed_at: SystemTime,

    /// TTL for this entry
    pub ttl: Duration,

    /// Entry size in bytes
    pub size_bytes: u64,

    /// Namespace
    pub namespace: String,

    /// Access count
    pub access_count: u64,

    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl<T> CacheEntry<T> {
    /// Create a new cache entry
    pub fn new(data: T, key: String, namespace: String) -> Self
    where
        T: serde::Serialize,
    {
        let serialized = serde_json::to_vec(&data).unwrap_or_default();
        let size_bytes = serialized.len() as u64;

        Self {
            data,
            key,
            created_at: SystemTime::now(),
            accessed_at: SystemTime::now(),
            ttl: Duration::from_secs(3600), // Default 1 hour
            size_bytes,
            namespace,
            access_count: 0,
            metadata: HashMap::new(),
        }
    }

    /// Set TTL for this entry
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Check if entry has expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now().duration_since(self.created_at).unwrap_or(Duration::MAX) > self.ttl
    }

    /// Update access timestamp and count
    pub fn mark_accessed(&mut self) {
        self.accessed_at = SystemTime::now();
        self.access_count += 1;
    }
}

/// Cache key generator for creating consistent cache keys
pub struct CacheKeyGenerator;

impl CacheKeyGenerator {
    /// Generate cache key for scan result
    pub fn for_scan_result(target: &ScanTarget, config: &HashMap<String, String>) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Add target information
        hasher.update(format!("{:?}", target).as_bytes());

        // Add configuration hash
        let mut config_items: Vec<_> = config.iter().collect();
        config_items.sort_by_key(|(k, _)| *k);
        for (key, value) in config_items {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }

        format!("scan_result:{}", hex::encode(hasher.finalize()))
    }

    /// Generate cache key for vulnerability data
    pub fn for_vulnerability_data(ecosystem: &str, package: &str, version: &str) -> String {
        format!("vulnerability:{}:{}:{}", ecosystem, package, version)
    }

    /// Generate cache key for artifact analysis
    pub fn for_artifact_analysis(target: &ScanTarget) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", target).as_bytes());

        format!("artifact:{}", hex::encode(hasher.finalize()))
    }

    /// Generate cache key for file content
    pub fn for_file_content(file_path: &str, checksum: &str) -> String {
        format!("file:{}:{}", file_path, checksum)
    }

    /// Generate cache key for custom data
    pub fn custom(namespace: &str, key: &str) -> String {
        format!("custom:{}:{}", namespace, key)
    }
}

/// Main cache interface trait
#[async_trait]
pub trait Cache: Send + Sync {
    /// Get value from cache
    async fn get<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de> + Send;

    /// Put value in cache
    async fn put<T>(&self, key: &str, value: T, ttl: Option<Duration>) -> Result<()>
    where
        T: Serialize + Send;

    /// Delete value from cache
    async fn delete(&self, key: &str) -> Result<bool>;

    /// Check if key exists in cache
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Clear all entries from cache
    async fn clear(&self) -> Result<()>;

    /// Get cache statistics
    async fn stats(&self) -> Result<CacheStats>;

    /// Cleanup expired entries
    async fn cleanup(&self) -> Result<usize>;
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total number of entries
    pub total_entries: usize,

    /// Total size in bytes
    pub total_size_bytes: u64,

    /// Number of hits
    pub hits: u64,

    /// Number of misses
    pub misses: u64,

    /// Hit rate percentage
    pub hit_rate: f64,

    /// Number of evictions
    pub evictions: u64,

    /// Average response time
    pub avg_response_time_ms: f64,

    /// Last cleanup timestamp
    pub last_cleanup: Option<SystemTime>,
}

/// Hybrid cache implementation combining memory and disk storage
pub struct HybridCache {
    memory_cache: Arc<dashmap::DashMap<String, CacheEntry<serde_json::Value>>>,
    disk_cache: Option<backend::DiskCache>,
    config: CacheConfig,
    metrics: metrics::CacheMetrics,
}

impl HybridCache {
    /// Create a new hybrid cache
    pub async fn new(config: CacheConfig) -> Result<Self> {
        info!("Initializing hybrid cache with config: {:?}", config);

        // Create cache directory if it doesn't exist
        std::fs::create_dir_all(&config.cache_dir)?;

        // Initialize disk cache if needed
        let disk_cache = match config.backend {
            CacheBackend::Disk | CacheBackend::Hybrid => {
                Some(backend::DiskCache::new(&config).await?)
            }
            CacheBackend::Memory => None,
        };

        // Initialize metrics
        let metrics = metrics::CacheMetrics::new(config.enable_metrics);

        Ok(Self {
            memory_cache: Arc::new(dashmap::DashMap::new()),
            disk_cache,
            config,
            metrics,
        })
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let memory_cache = self.memory_cache.clone();
        let disk_cache = self.disk_cache.clone();
        let cleanup_interval = self.config.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);

            loop {
                interval.tick().await;

                // Cleanup memory cache
                let mut removed_memory = 0;
                memory_cache.retain(|_, entry| {
                    if entry.is_expired() {
                        removed_memory += 1;
                        false
                    } else {
                        true
                    }
                });

                // Cleanup disk cache
                if let Some(ref disk) = disk_cache {
                    if let Ok(removed_disk) = disk.cleanup().await {
                        debug!("Cleaned up {} expired entries from disk cache", removed_disk);
                    }
                }

                if removed_memory > 0 {
                    debug!("Cleaned up {} expired entries from memory cache", removed_memory);
                }
            }
        })
    }
}

#[async_trait]
impl Cache for HybridCache {
    async fn get<T>(&self, key: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de> + Send,
    {
        let start_time = SystemTime::now();
        self.metrics.record_operation("get");

        // Try memory cache first
        if let Some(entry) = self.memory_cache.get(key) {
            if !entry.is_expired() {
                entry.mark_accessed();
                self.metrics.record_hit();

                let response_time = start_time.elapsed().unwrap_or_default();
                self.metrics.record_response_time(response_time);

                return Ok(serde_json::from_value(entry.data.clone()).ok());
            } else {
                // Entry expired, remove it
                self.memory_cache.remove(key);
            }
        }

        // Try disk cache
        if let Some(ref disk) = self.disk_cache {
            if let Some(data) = disk.get(key).await? {
                // Deserialize and check if still valid
                if let Ok(entry) = serde_json::from_slice::<CacheEntry<serde_json::Value>>(&data) {
                    if !entry.is_expired() {
                        // Put back in memory cache for faster future access
                        let memory_entry = CacheEntry {
                            data: entry.data.clone(),
                            key: entry.key,
                            created_at: entry.created_at,
                            accessed_at: SystemTime::now(),
                            ttl: entry.ttl,
                            size_bytes: entry.size_bytes,
                            namespace: entry.namespace,
                            access_count: entry.access_count + 1,
                            metadata: entry.metadata,
                        };
                        self.memory_cache.insert(key.to_string(), memory_entry);

                        self.metrics.record_hit();
                        let response_time = start_time.elapsed().unwrap_or_default();
                        self.metrics.record_response_time(response_time);

                        return Ok(serde_json::from_value(entry.data).ok());
                    }
                }
            }
        }

        self.metrics.record_miss();
        let response_time = start_time.elapsed().unwrap_or_default();
        self.metrics.record_response_time(response_time);

        Ok(None)
    }

    async fn put<T>(&self, key: &str, value: T, ttl: Option<Duration>) -> Result<()>
    where
        T: Serialize + Send,
    {
        self.metrics.record_operation("put");

        let serialized = serde_json::to_vec(&value)?;
        let size_bytes = serialized.len() as u64;

        // Check size limits
        if self.config.max_size_bytes > 0 && size_bytes > self.config.max_size_bytes {
            return Err(anyhow::anyhow!("Cache entry too large: {} bytes", size_bytes));
        }

        // Check entry limits
        if self.config.max_entries > 0 && self.memory_cache.len() >= self.config.max_entries {
            // Evict some entries
            self.evict_entries().await?;
        }

        let ttl = ttl.unwrap_or(self.config.default_ttl);

        let entry = CacheEntry::new(value, key.to_string(), "default".to_string())
            .with_ttl(ttl);

        // Store in memory cache
        self.memory_cache.insert(key.to_string(), entry);

        // Store in disk cache if available
        if let Some(ref disk) = self.disk_cache {
            disk.put(key, &serialized, ttl).await?;
        }

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        self.metrics.record_operation("delete");

        let mut deleted = false;

        // Remove from memory cache
        if self.memory_cache.remove(key).is_some() {
            deleted = true;
        }

        // Remove from disk cache
        if let Some(ref disk) = self.disk_cache {
            if disk.delete(key).await? {
                deleted = true;
            }
        }

        Ok(deleted)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        // Check memory cache
        if let Some(entry) = self.memory_cache.get(key) {
            if !entry.is_expired() {
                return Ok(true);
            }
        }

        // Check disk cache
        if let Some(ref disk) = self.disk_cache {
            return disk.exists(key).await;
        }

        Ok(false)
    }

    async fn clear(&self) -> Result<()> {
        info!("Clearing cache");

        // Clear memory cache
        self.memory_cache.clear();

        // Clear disk cache
        if let Some(ref disk) = self.disk_cache {
            disk.clear().await?;
        }

        Ok(())
    }

    async fn stats(&self) -> Result<CacheStats> {
        let total_entries = self.memory_cache.len();
        let total_size_bytes = self.memory_cache.iter().map(|entry| entry.size_bytes).sum();

        let (hits, misses) = self.metrics.get_hit_stats();
        let hit_rate = if hits + misses > 0 {
            (hits as f64) / ((hits + misses) as f64) * 100.0
        } else {
            0.0
        };

        let avg_response_time_ms = self.metrics.get_avg_response_time_ms();
        let evictions = self.metrics.get_evictions();
        let last_cleanup = self.metrics.get_last_cleanup();

        Ok(CacheStats {
            total_entries,
            total_size_bytes,
            hits,
            misses,
            hit_rate,
            evictions,
            avg_response_time_ms,
            last_cleanup,
        })
    }

    async fn cleanup(&self) -> Result<usize> {
        let mut removed = 0;

        // Cleanup memory cache
        let initial_count = self.memory_cache.len();
        self.memory_cache.retain(|_, entry| {
            if entry.is_expired() {
                removed += 1;
                false
            } else {
                true
            }
        });

        debug!("Removed {} expired entries from memory cache", removed);

        // Cleanup disk cache
        if let Some(ref disk) = self.disk_cache {
            let disk_removed = disk.cleanup().await?;
            removed += disk_removed;
        }

        Ok(removed)
    }

    /// Evict entries based on LRU policy
    async fn evict_entries(&self) -> Result<()> {
        // Simple LRU eviction: remove oldest entries
        let mut entries: Vec<_> = self.memory_cache.iter().map(|entry| entry.clone()).collect();
        entries.sort_by_key(|entry| entry.accessed_at);

        let to_remove = (entries.len() / 4).max(10); // Remove 25% or at least 10 entries

        for entry in entries.iter().take(to_remove) {
            self.memory_cache.remove(&entry.key);
            self.metrics.record_eviction();
        }

        debug!("Evicted {} entries from cache", to_remove);
        Ok(())
    }
}

/// Cache manager for coordinating multiple cache instances
pub struct CacheManager {
    caches: HashMap<String, Box<dyn Cache>>,
    default_cache: String,
    config: CacheConfig,
}

impl CacheManager {
    /// Create a new cache manager
    pub async fn new(config: CacheConfig) -> Result<Self> {
        let mut manager = Self {
            caches: HashMap::new(),
            default_cache: "default".to_string(),
            config,
        };

        // Create default cache
        let default_cache = Box::new(HybridCache::new(config.clone()).await?);
        manager.caches.insert("default".to_string(), default_cache);

        // Create namespace-specific caches
        for namespace in &config.namespaces {
            let namespace_cache = Box::new(HybridCache::new(config.clone()).await?);
            manager.caches.insert(namespace.clone(), namespace_cache);
        }

        info!("Cache manager initialized with {} caches", manager.caches.len());
        Ok(manager)
    }

    /// Get cache by name
    pub fn get_cache(&self, name: &str) -> Option<&Box<dyn Cache>> {
        self.caches.get(name)
    }

    /// Get default cache
    pub fn get_default_cache(&self) -> &Box<dyn Cache> {
        self.caches.get(&self.default_cache).unwrap()
    }

    /// Get or create cache for namespace
    pub async fn get_namespace_cache(&mut self, namespace: &str) -> Result<&Box<dyn Cache>> {
        if !self.caches.contains_key(namespace) {
            let namespace_config = CacheConfig {
                cache_dir: self.config.cache_dir.join(namespace),
                ..self.config.clone()
            };

            let cache = Box::new(HybridCache::new(namespace_config).await?);
            self.caches.insert(namespace.to_string(), cache);
        }

        Ok(self.caches.get(namespace).unwrap())
    }

    /// Get all cache statistics
    pub async fn get_all_stats(&self) -> Result<HashMap<String, CacheStats>> {
        let mut stats = HashMap::new();

        for (name, cache) in &self.caches {
            if let Ok(cache_stats) = cache.stats().await {
                stats.insert(name.clone(), cache_stats);
            }
        }

        Ok(stats)
    }

    /// Clear all caches
    pub async fn clear_all(&self) -> Result<()> {
        for cache in self.caches.values() {
            cache.clear().await?;
        }
        Ok(())
    }

    /// Cleanup all caches
    pub async fn cleanup_all(&self) -> Result<usize> {
        let mut total_removed = 0;

        for cache in self.caches.values() {
            if let Ok(removed) = cache.cleanup().await {
                total_removed += removed;
            }
        }

        Ok(total_removed)
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self {
            caches: HashMap::new(),
            default_cache: "default".to_string(),
            config: CacheConfig::default(),
        }
    }
}

/// Global cache instance
static CACHE_MANAGER: once_cell::sync::OnceCell<CacheManager> = once_cell::sync::OnceCell::new();

/// Initialize global cache manager
pub async fn init_cache(config: CacheConfig) -> Result<()> {
    let manager = CacheManager::new(config).await?;
    CACHE_MANAGER.set(manager).map_err(|_| anyhow::anyhow!("Cache manager already initialized"))?;
    Ok(())
}

/// Get global cache manager
pub fn get_cache_manager() -> Option<&'static CacheManager> {
    CACHE_MANAGER.get()
}

/// Convenience functions for common caching operations
pub mod cache_utils {
    use super::*;

    /// Cache scan result
    pub async fn cache_scan_result(
        target: &ScanTarget,
        config: &HashMap<String, String>,
        result: &ScanResult,
    ) -> Result<()> {
        if let Some(manager) = get_cache_manager() {
            let cache = manager.get_default_cache();
            let key = CacheKeyGenerator::for_scan_result(target, config);
            cache.put(&key, result, Some(Duration::from_secs(3600))).await?;
        }
        Ok(())
    }

    /// Get cached scan result
    pub async fn get_cached_scan_result(
        target: &ScanTarget,
        config: &HashMap<String, String>,
    ) -> Result<Option<ScanResult>> {
        if let Some(manager) = get_cache_manager() {
            let cache = manager.get_default_cache();
            let key = CacheKeyGenerator::for_scan_result(target, config);
            Ok(cache.get::<ScanResult>(&key).await?)
        } else {
            Ok(None)
        }
    }

    /// Cache vulnerability data
    pub async fn cache_vulnerability_data(
        ecosystem: &str,
        package: &str,
        version: &str,
        vulnerabilities: &[deepsys_types::Vulnerability],
    ) -> Result<()> {
        if let Some(manager) = get_cache_manager() {
            let cache = manager.get_namespace_cache("vulnerabilities").await?;
            let key = CacheKeyGenerator::for_vulnerability_data(ecosystem, package, version);
            cache.put(&key, vulnerabilities, Some(Duration::from_secs(7200))).await?; // 2 hours
        }
        Ok(())
    }

    /// Get cached vulnerability data
    pub async fn get_cached_vulnerability_data(
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<Vec<deepsys_types::Vulnerability>>> {
        if let Some(manager) = get_cache_manager() {
            let cache = manager.get_namespace_cache("vulnerabilities").await?;
            let key = CacheKeyGenerator::for_vulnerability_data(ecosystem, package, version);
            Ok(cache.get::<Vec<deepsys_types::Vulnerability>>(&key).await?)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_generation() {
        let target = ScanTarget::Filesystem {
            path: "/test".to_string(),
            recursive: true,
        };

        let config = HashMap::from([
            ("enable_vulnerabilities".to_string(), "true".to_string()),
            ("enable_secrets".to_string(), "false".to_string()),
        ]);

        let key = CacheKeyGenerator::for_scan_result(&target, &config);
        assert!(key.starts_with("scan_result:"));
        assert!(key.len() > 20); // Should be a hash
    }

    #[test]
    fn test_cache_entry() {
        let data = "test data";
        let entry = CacheEntry::new(data, "test-key".to_string(), "test-namespace".to_string())
            .with_ttl(Duration::from_secs(60));

        assert_eq!(entry.key, "test-key");
        assert_eq!(entry.namespace, "test-namespace");
        assert_eq!(entry.ttl, Duration::from_secs(60));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();

        assert!(config.enabled);
        assert_eq!(config.backend, CacheBackend::Hybrid);
        assert_eq!(config.default_ttl, Duration::from_secs(3600));
        assert!(config.max_size_bytes > 0);
    }

    #[tokio::test]
    async fn test_hybrid_cache_creation() {
        let config = CacheConfig::default();
        let cache = HybridCache::new(config).await;

        assert!(cache.is_ok());

        if let Ok(cache) = cache {
            let stats = cache.stats().await.unwrap();
            assert_eq!(stats.total_entries, 0);
            assert_eq!(stats.hit_rate, 0.0);
        }
    }
}
