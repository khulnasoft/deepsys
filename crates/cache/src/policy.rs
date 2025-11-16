//! # Cache Policies
//!
//! Eviction policies and cache management strategies for optimizing
//! cache performance and memory usage.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::CacheEntry;

/// Cache eviction policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvictionPolicy {
    /// Least Recently Used (LRU)
    LRU,
    /// Least Frequently Used (LFU)
    LFU,
    /// Time-based expiration only (no eviction)
    TTLOnly,
    /// Random eviction
    Random,
    /// Size-based eviction
    SizeBased,
}

/// Cache entry with LRU metadata
#[derive(Debug, Clone)]
struct LRUEntry<T> {
    entry: CacheEntry<T>,
    last_accessed: SystemTime,
}

impl<T> LRUEntry<T> {
    fn new(entry: CacheEntry<T>) -> Self {
        Self {
            entry,
            last_accessed: SystemTime::now(),
        }
    }

    fn update_access(&mut self) {
        self.last_accessed = SystemTime::now();
        self.entry.mark_accessed();
    }
}

/// Cache entry with LFU metadata
#[derive(Debug, Clone)]
struct LFUEntry<T> {
    entry: CacheEntry<T>,
    frequency: u64,
}

impl<T> LFUEntry<T> {
    fn new(entry: CacheEntry<T>) -> Self {
        Self {
            entry,
            frequency: 1,
        }
    }

    fn increment_frequency(&mut self) {
        self.frequency += 1;
        self.entry.mark_accessed();
    }
}

/// LRU cache implementation
pub struct LRUCache<T> {
    entries: HashMap<String, LRUEntry<T>>,
    max_entries: usize,
    access_order: std::collections::VecDeque<String>,
}

impl<T> LRUCache<T>
where
    T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            access_order: std::collections::VecDeque::new(),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<&T> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.update_access();
            self.update_access_order(key);
            Some(&entry.entry.data)
        } else {
            None
        }
    }

    pub fn put(&mut self, key: String, value: T, ttl: Duration) -> Result<()> {
        // Check if we need to evict
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&key) {
            self.evict_lru()?;
        }

        let mut entry = CacheEntry::new(value, key.clone(), "lru".to_string())
            .with_ttl(ttl);

        entry.mark_accessed();

        let lru_entry = LRUEntry::new(entry);

        self.entries.insert(key.clone(), lru_entry);
        self.access_order.push_back(key);

        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> bool {
        if let Some(_) = self.entries.remove(key) {
            self.access_order.retain(|k| k != key);
            true
        } else {
            false
        }
    }

    pub fn cleanup(&mut self) -> usize {
        let mut removed = 0;
        let mut keys_to_remove = Vec::new();

        for (key, entry) in &self.entries {
            if entry.entry.is_expired() {
                keys_to_remove.push(key.clone());
            }
        }

        for key in keys_to_remove {
            self.entries.remove(&key);
            self.access_order.retain(|k| k != &key);
            removed += 1;
        }

        removed
    }

    fn update_access_order(&mut self, key: &str) {
        self.access_order.retain(|k| k != key);
        self.access_order.push_back(key.to_string());
    }

    fn evict_lru(&mut self) -> Result<()> {
        while let Some(oldest_key) = self.access_order.pop_front() {
            if self.entries.remove(&oldest_key).is_some() {
                break;
            }
        }
        Ok(())
    }

    pub fn stats(&self) -> LRUStats {
        LRUStats {
            total_entries: self.entries.len(),
            max_entries: self.max_entries,
            hit_rate: 0.0, // Would need hit/miss tracking
        }
    }
}

/// LRU cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LRUStats {
    pub total_entries: usize,
    pub max_entries: usize,
    pub hit_rate: f64,
}

/// LFU cache implementation
pub struct LFUCache<T> {
    entries: HashMap<String, LFUEntry<T>>,
    max_entries: usize,
    frequency_order: std::collections::BTreeMap<u64, Vec<String>>,
}

impl<T> LFUCache<T>
where
    T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            frequency_order: std::collections::BTreeMap::new(),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<&T> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.increment_frequency();
            self.update_frequency_order(key, entry.frequency);
            Some(&entry.entry.data)
        } else {
            None
        }
    }

    pub fn put(&mut self, key: String, value: T, ttl: Duration) -> Result<()> {
        // Check if we need to evict
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&key) {
            self.evict_lfu()?;
        }

        let mut entry = CacheEntry::new(value, key.clone(), "lfu".to_string())
            .with_ttl(ttl);

        entry.mark_accessed();

        let frequency = 1;
        let lfu_entry = LFUEntry::new(entry);

        self.entries.insert(key.clone(), lfu_entry);
        self.frequency_order.entry(frequency).or_insert_with(Vec::new).push(key);

        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> bool {
        if let Some(entry) = self.entries.remove(key) {
            if let Some(keys) = self.frequency_order.get_mut(&entry.frequency) {
                keys.retain(|k| k != key);
                if keys.is_empty() {
                    self.frequency_order.remove(&entry.frequency);
                }
            }
            true
        } else {
            false
        }
    }

    pub fn cleanup(&mut self) -> usize {
        let mut removed = 0;
        let mut keys_to_remove = Vec::new();

        for (key, entry) in &self.entries {
            if entry.entry.is_expired() {
                keys_to_remove.push(key.clone());
            }
        }

        for key in keys_to_remove {
            self.remove(&key);
            removed += 1;
        }

        removed
    }

    fn update_frequency_order(&mut self, key: &str, new_frequency: u64) {
        // Remove from old frequency
        if let Some(entry) = self.entries.get(key) {
            if let Some(old_keys) = self.frequency_order.get_mut(&entry.frequency) {
                old_keys.retain(|k| k != key);
                if old_keys.is_empty() {
                    self.frequency_order.remove(&entry.frequency);
                }
            }
        }

        // Add to new frequency
        self.frequency_order.entry(new_frequency).or_insert_with(Vec::new).push(key.to_string());
    }

    fn evict_lfu(&mut self) -> Result<()> {
        // Find lowest frequency with entries
        if let Some((frequency, keys)) = self.frequency_order.iter().next().cloned() {
            if let Some(key_to_remove) = keys.first() {
                self.remove(key_to_remove);
            }
        }
        Ok(())
    }

    pub fn stats(&self) -> LFUStats {
        LFUStats {
            total_entries: self.entries.len(),
            max_entries: self.max_entries,
            min_frequency: self.frequency_order.keys().next().copied().unwrap_or(0),
            max_frequency: self.frequency_order.keys().last().copied().unwrap_or(0),
        }
    }
}

/// LFU cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LFUStats {
    pub total_entries: usize,
    pub max_entries: usize,
    pub min_frequency: u64,
    pub max_frequency: u64,
}

/// Cache policy manager
pub struct PolicyManager {
    policy: EvictionPolicy,
    lru_cache: Option<HashMap<String, LRUCache<serde_json::Value>>>,
    lfu_cache: Option<HashMap<String, LFUCache<serde_json::Value>>>,
}

impl PolicyManager {
    pub fn new(policy: EvictionPolicy) -> Self {
        Self {
            policy,
            lru_cache: None,
            lfu_cache: None,
        }
    }

    pub fn apply_policy<T>(
        &mut self,
        entries: &mut HashMap<String, CacheEntry<T>>,
        max_entries: usize,
    ) -> Result<usize>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        match self.policy {
            EvictionPolicy::LRU => {
                self.apply_lru_policy(entries, max_entries)
            }
            EvictionPolicy::LFU => {
                self.apply_lfu_policy(entries, max_entries)
            }
            EvictionPolicy::TTLOnly => {
                self.apply_ttl_policy(entries)
            }
            EvictionPolicy::Random => {
                self.apply_random_policy(entries, max_entries)
            }
            EvictionPolicy::SizeBased => {
                self.apply_size_policy(entries, max_entries)
            }
        }
    }

    fn apply_lru_policy<T>(
        &self,
        entries: &mut HashMap<String, CacheEntry<T>>,
        max_entries: usize,
    ) -> Result<usize>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let mut evicted = 0;

        // Sort entries by access time (oldest first)
        let mut sorted_entries: Vec<_> = entries.iter().collect();
        sorted_entries.sort_by_key(|(_, entry)| entry.accessed_at);

        // Remove oldest entries beyond limit
        while entries.len() > max_entries && !sorted_entries.is_empty() {
            if let Some((key, _)) = sorted_entries.remove(0) {
                entries.remove(key);
                evicted += 1;
            }
        }

        Ok(evicted)
    }

    fn apply_lfu_policy<T>(
        &self,
        entries: &mut HashMap<String, CacheEntry<T>>,
        max_entries: usize,
    ) -> Result<usize>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let mut evicted = 0;

        // Sort entries by access count (least frequent first)
        let mut sorted_entries: Vec<_> = entries.iter().collect();
        sorted_entries.sort_by_key(|(_, entry)| entry.access_count);

        // Remove least frequently used entries beyond limit
        while entries.len() > max_entries && !sorted_entries.is_empty() {
            if let Some((key, _)) = sorted_entries.remove(0) {
                entries.remove(key);
                evicted += 1;
            }
        }

        Ok(evicted)
    }

    fn apply_ttl_policy<T>(&self, entries: &mut HashMap<String, CacheEntry<T>>) -> Result<usize>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let mut removed = 0;
        let mut keys_to_remove = Vec::new();

        for (key, entry) in entries.iter() {
            if entry.is_expired() {
                keys_to_remove.push(key.clone());
            }
        }

        for key in keys_to_remove {
            entries.remove(&key);
            removed += 1;
        }

        Ok(removed)
    }

    fn apply_random_policy<T>(
        &self,
        entries: &mut HashMap<String, CacheEntry<T>>,
        max_entries: usize,
    ) -> Result<usize>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let mut evicted = 0;
        let keys: Vec<String> = entries.keys().cloned().collect();

        while entries.len() > max_entries && !keys.is_empty() {
            // Randomly select an entry to evict
            use rand::Rng;
            let mut rng = rand::thread_rng();
            if let Some(random_index) = keys.get(rng.gen_range(0..keys.len())) {
                entries.remove(random_index);
                evicted += 1;
            }
        }

        Ok(evicted)
    }

    fn apply_size_policy<T>(
        &self,
        entries: &mut HashMap<String, CacheEntry<T>>,
        max_size: usize,
    ) -> Result<usize>
    where
        T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let mut evicted = 0;
        let mut total_size = entries.values().map(|e| e.size_bytes).sum::<u64>() as usize;

        // Sort entries by size (largest first)
        let mut sorted_entries: Vec<_> = entries.iter().collect();
        sorted_entries.sort_by_key(|(_, entry)| entry.size_bytes);

        // Remove largest entries until under size limit
        while total_size > max_size && !sorted_entries.is_empty() {
            if let Some((key, entry)) = sorted_entries.pop() {
                entries.remove(key);
                total_size -= entry.size_bytes as usize;
                evicted += 1;
            }
        }

        Ok(evicted)
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new(EvictionPolicy::LRU)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_cache() {
        let mut cache = LRUCache::new(3);

        // Add entries
        cache.put("key1".to_string(), "value1".to_string(), Duration::from_secs(60)).unwrap();
        cache.put("key2".to_string(), "value2".to_string(), Duration::from_secs(60)).unwrap();
        cache.put("key3".to_string(), "value3".to_string(), Duration::from_secs(60)).unwrap();

        assert_eq!(cache.entries.len(), 3);

        // Access key1 (should make it most recently used)
        assert_eq!(cache.get("key1"), Some(&"value1".to_string()));

        // Add key4 (should evict key2, the least recently used)
        cache.put("key4".to_string(), "value4".to_string(), Duration::from_secs(60)).unwrap();

        assert_eq!(cache.entries.len(), 3);
        assert!(cache.get("key1").is_some()); // Most recently used
        assert!(cache.get("key3").is_some()); // Recently used
        assert!(cache.get("key4").is_some()); // Newly added
        assert!(cache.get("key2").is_none()); // Evicted
    }

    #[test]
    fn test_policy_manager() {
        let mut manager = PolicyManager::new(EvictionPolicy::LRU);
        let mut entries = HashMap::new();

        // Add test entries
        entries.insert("key1".to_string(), CacheEntry::new("value1", "key1".to_string(), "test".to_string()));
        entries.insert("key2".to_string(), CacheEntry::new("value2", "key2".to_string(), "test".to_string()));
        entries.insert("key3".to_string(), CacheEntry::new("value3", "key3".to_string(), "test".to_string()));

        // Apply LRU policy
        let evicted = manager.apply_lru_policy(&mut entries, 2).unwrap();

        assert_eq!(evicted, 1);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_eviction_policy_serialization() {
        let policy = EvictionPolicy::LRU;
        let serialized = serde_json::to_string(&policy).unwrap();
        let deserialized: EvictionPolicy = serde_json::from_str(&serialized).unwrap();

        assert_eq!(policy, deserialized);
    }
}
