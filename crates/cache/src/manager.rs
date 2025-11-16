//! # Cache Manager
//!
//! High-level cache management and coordination for multiple cache instances
//! and different caching strategies.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::{Cache, CacheConfig, CacheStats};

/// Advanced cache manager with multiple strategies
pub struct AdvancedCacheManager {
    caches: HashMap<String, Box<dyn Cache>>,
    config: CacheConfig,
    strategies: Vec<CacheStrategy>,
}

impl AdvancedCacheManager {
    /// Create a new advanced cache manager
    pub async fn new(config: CacheConfig) -> Result<Self> {
        let mut manager = Self {
            caches: HashMap::new(),
            config,
            strategies: Vec::new(),
        };

        // Initialize default cache
        let default_cache = crate::CacheFactory::create_cache(config.clone()).await?;
        manager.caches.insert("default".to_string(), default_cache);

        // Add default strategies
        manager.add_strategy(CacheStrategy::LRU);
        manager.add_strategy(CacheStrategy::SizeBased);

        Ok(manager)
    }

    /// Add a caching strategy
    pub fn add_strategy(&mut self, strategy: CacheStrategy) {
        self.strategies.push(strategy);
    }

    /// Get cache by name
    pub fn get_cache(&self, name: &str) -> Option<&Box<dyn Cache>> {
        self.caches.get(name)
    }

    /// Get or create cache for specific use case
    pub async fn get_specialized_cache(&mut self, cache_type: &str) -> Result<&Box<dyn Cache>> {
        if !self.caches.contains_key(cache_type) {
            let specialized_config = CacheConfig {
                cache_dir: self.config.cache_dir.join(cache_type),
                max_entries: self.get_max_entries_for_type(cache_type),
                ..self.config.clone()
            };

            let cache = crate::CacheFactory::create_cache(specialized_config).await?;
            self.caches.insert(cache_type.to_string(), cache);
        }

        Ok(self.caches.get(cache_type).unwrap())
    }

    /// Apply caching strategies
    pub async fn apply_strategies(&self) -> Result<()> {
        for strategy in &self.strategies {
            match strategy {
                CacheStrategy::LRU => {
                    self.apply_lru_strategy().await?;
                }
                CacheStrategy::SizeBased => {
                    self.apply_size_strategy().await?;
                }
                CacheStrategy::TTLBased => {
                    self.apply_ttl_strategy().await?;
                }
                CacheStrategy::Adaptive => {
                    self.apply_adaptive_strategy().await?;
                }
            }
        }

        Ok(())
    }

    async fn apply_lru_strategy(&self) -> Result<()> {
        // Implementation would apply LRU optimization across caches
        debug!("Applying LRU strategy");
        Ok(())
    }

    async fn apply_size_strategy(&self) -> Result<()> {
        // Implementation would optimize based on cache size
        debug!("Applying size-based strategy");
        Ok(())
    }

    async fn apply_ttl_strategy(&self) -> Result<()> {
        // Implementation would optimize TTL settings
        debug!("Applying TTL-based strategy");
        Ok(())
    }

    async fn apply_adaptive_strategy(&self) -> Result<()> {
        // Implementation would adapt based on usage patterns
        debug!("Applying adaptive strategy");
        Ok(())
    }

    fn get_max_entries_for_type(&self, cache_type: &str) -> usize {
        match cache_type {
            "vulnerabilities" => 5000,
            "scan_results" => 1000,
            "artifacts" => 2000,
            "files" => 10000,
            _ => 1000,
        }
    }

    /// Get comprehensive statistics
    pub async fn get_comprehensive_stats(&self) -> Result<ComprehensiveStats> {
        let mut stats = HashMap::new();
        let mut total_entries = 0;
        let mut total_size = 0;
        let mut total_hits = 0;
        let mut total_misses = 0;

        for (name, cache) in &self.caches {
            if let Ok(cache_stats) = cache.stats().await {
                stats.insert(name.clone(), cache_stats.clone());
                total_entries += cache_stats.total_entries;
                total_size += cache_stats.total_size_bytes;
                total_hits += cache_stats.hits;
                total_misses += cache_stats.misses;
            }
        }

        let overall_hit_rate = if total_hits + total_misses > 0 {
            (total_hits as f64) / ((total_hits + total_misses) as f64) * 100.0
        } else {
            0.0
        };

        Ok(ComprehensiveStats {
            cache_stats: stats,
            total_entries,
            total_size_bytes: total_size,
            total_hits,
            total_misses,
            overall_hit_rate,
            strategies: self.strategies.clone(),
        })
    }

    /// Optimize cache configuration based on usage
    pub async fn optimize(&mut self) -> Result<OptimizationReport> {
        let stats = self.get_comprehensive_stats().await?;

        let mut recommendations = Vec::new();

        // Analyze hit rates
        for (cache_name, cache_stats) in &stats.cache_stats {
            if cache_stats.hit_rate < 50.0 {
                recommendations.push(OptimizationRecommendation {
                    cache_name: cache_name.clone(),
                    recommendation_type: RecommendationType::IncreaseSize,
                    description: format!("Low hit rate ({:.1}%) - consider increasing cache size", cache_stats.hit_rate),
                    suggested_action: "Increase max_entries or max_size_bytes".to_string(),
                });
            }

            if cache_stats.avg_response_time_ms > 10.0 {
                recommendations.push(OptimizationRecommendation {
                    cache_name: cache_name.clone(),
                    recommendation_type: RecommendationType::ImprovePerformance,
                    description: format!("High response time ({:.1}ms)", cache_stats.avg_response_time_ms),
                    suggested_action: "Consider switching to memory-only cache or optimizing key generation".to_string(),
                });
            }
        }

        // Check for overall optimization opportunities
        if stats.overall_hit_rate < 60.0 {
            recommendations.push(OptimizationRecommendation {
                cache_name: "all".to_string(),
                recommendation_type: RecommendationType::GeneralOptimization,
                description: format!("Overall hit rate is low ({:.1}%)", stats.overall_hit_rate),
                suggested_action: "Review cache key generation and TTL settings".to_string(),
            });
        }

        Ok(OptimizationReport {
            current_stats: stats,
            recommendations,
        })
    }
}

/// Cache strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheStrategy {
    LRU,
    SizeBased,
    TTLBased,
    Adaptive,
}

/// Comprehensive cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveStats {
    pub cache_stats: HashMap<String, CacheStats>,
    pub total_entries: usize,
    pub total_size_bytes: u64,
    pub total_hits: u64,
    pub total_misses: u64,
    pub overall_hit_rate: f64,
    pub strategies: Vec<CacheStrategy>,
}

/// Optimization recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecommendation {
    pub cache_name: String,
    pub recommendation_type: RecommendationType,
    pub description: String,
    pub suggested_action: String,
}

/// Recommendation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationType {
    IncreaseSize,
    ImprovePerformance,
    GeneralOptimization,
    StrategyChange,
}

/// Optimization report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub current_stats: ComprehensiveStats,
    pub recommendations: Vec<OptimizationRecommendation>,
}

/// Cache performance monitor
pub struct PerformanceMonitor {
    manager: Arc<AdvancedCacheManager>,
}

impl PerformanceMonitor {
    pub fn new(manager: Arc<AdvancedCacheManager>) -> Self {
        Self { manager }
    }

    /// Start monitoring performance
    pub async fn start_monitoring(&self) -> Result<()> {
        let manager = self.manager.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Monitor every minute

            loop {
                interval.tick().await;

                // Get current stats
                if let Ok(stats) = manager.get_comprehensive_stats().await {
                    debug!("Cache performance: {} entries, {:.1}% hit rate, {:.1}MB",
                           stats.total_entries,
                           stats.overall_hit_rate,
                           stats.total_size_bytes as f64 / 1024.0 / 1024.0);

                    // Check if optimization is needed
                    if stats.overall_hit_rate < 50.0 {
                        warn!("Low cache hit rate detected: {:.1}%", stats.overall_hit_rate);
                    }
                }
            }
        });

        Ok(())
    }

    /// Generate performance report
    pub async fn generate_report(&self) -> Result<String> {
        let stats = self.manager.get_comprehensive_stats().await?;

        Ok(format!(
            "Cache Performance Report\n\
             ========================\n\
             \n\
             Overall Statistics:\n\
             - Total Entries: {}\n\
             - Total Size: {:.2} MB\n\
             - Hit Rate: {:.1}%\n\
             - Total Hits: {}\n\
             - Total Misses: {}\n\
             \n\
             Per-Cache Statistics:\n\
             {}\
             \n\
             Active Strategies: {:?}",
            stats.total_entries,
            stats.total_size_bytes as f64 / 1024.0 / 1024.0,
            stats.overall_hit_rate,
            stats.total_hits,
            stats.total_misses,
            stats.cache_stats.iter()
                .map(|(name, cache_stats)| format!(
                    "  {}: {} entries, {:.1}% hit rate, {:.1}ms avg response",
                    name,
                    cache_stats.total_entries,
                    cache_stats.hit_rate,
                    cache_stats.avg_response_time_ms
                ))
                .collect::<Vec<_>>()
                .join("\n"),
            stats.strategies
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advanced_cache_manager() {
        let config = CacheConfig::default();
        let manager = AdvancedCacheManager::new(config).await.unwrap();

        assert!(manager.caches.contains_key("default"));
        assert!(!manager.strategies.is_empty());
    }

    #[test]
    fn test_cache_strategies() {
        let strategies = vec![CacheStrategy::LRU, CacheStrategy::SizeBased];
        let serialized = serde_json::to_string(&strategies).unwrap();
        let deserialized: Vec<CacheStrategy> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(strategies, deserialized);
    }

    #[test]
    fn test_optimization_recommendations() {
        let recommendation = OptimizationRecommendation {
            cache_name: "test".to_string(),
            recommendation_type: RecommendationType::IncreaseSize,
            description: "Test recommendation".to_string(),
            suggested_action: "Test action".to_string(),
        };

        let serialized = serde_json::to_string(&recommendation).unwrap();
        let deserialized: OptimizationRecommendation = serde_json::from_str(&serialized).unwrap();

        assert_eq!(recommendation.cache_name, deserialized.cache_name);
    }
}
