//! # Cache Metrics
//!
//! Performance metrics and monitoring for cache operations.
//! Tracks hit rates, response times, evictions, and other cache statistics.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Cache metrics collector
pub struct CacheMetrics {
    enabled: bool,
    hits: AtomicU64,
    misses: AtomicU64,
    operations: AtomicU64,
    evictions: AtomicU64,
    response_times: std::sync::Mutex<Vec<Duration>>,
    operation_counts: std::sync::Mutex<HashMap<String, u64>>,
    last_cleanup: std::sync::Mutex<Option<SystemTime>>,
}

impl CacheMetrics {
    /// Create a new metrics collector
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            operations: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            response_times: std::sync::Mutex::new(Vec::new()),
            operation_counts: std::sync::Mutex::new(HashMap::new()),
            last_cleanup: std::sync::Mutex::new(None),
        }
    }

    /// Record a cache hit
    pub fn record_hit(&self) {
        if self.enabled {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.operations.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        if self.enabled {
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.operations.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record an eviction
    pub fn record_eviction(&self) {
        if self.enabled {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record operation type
    pub fn record_operation(&self, operation: &str) {
        if self.enabled {
            let mut counts = self.operation_counts.lock().unwrap();
            *counts.entry(operation.to_string()).or_insert(0) += 1;
        }
    }

    /// Record response time
    pub fn record_response_time(&self, duration: Duration) {
        if self.enabled {
            let mut times = self.response_times.lock().unwrap();
            times.push(duration);

            // Keep only last 1000 response times
            if times.len() > 1000 {
                times.remove(0);
            }
        }
    }

    /// Record cleanup operation
    pub fn record_cleanup(&self) {
        if self.enabled {
            *self.last_cleanup.lock().unwrap() = Some(SystemTime::now());
        }
    }

    /// Get hit statistics
    pub fn get_hit_stats(&self) -> (u64, u64) {
        (self.hits.load(Ordering::Relaxed), self.misses.load(Ordering::Relaxed))
    }

    /// Get average response time in milliseconds
    pub fn get_avg_response_time_ms(&self) -> f64 {
        if let Ok(times) = self.response_times.lock() {
            if !times.is_empty() {
                let total_ms: f64 = times.iter()
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .sum();
                total_ms / times.len() as f64
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    /// Get eviction count
    pub fn get_evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Get last cleanup timestamp
    pub fn get_last_cleanup(&self) -> Option<SystemTime> {
        *self.last_cleanup.lock().unwrap()
    }

    /// Get operation counts
    pub fn get_operation_counts(&self) -> HashMap<String, u64> {
        self.operation_counts.lock().unwrap().clone()
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.operations.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);

        *self.response_times.lock().unwrap() = Vec::new();
        *self.operation_counts.lock().unwrap() = HashMap::new();
        *self.last_cleanup.lock().unwrap() = None;
    }

    /// Generate metrics report
    pub fn generate_report(&self) -> MetricsReport {
        let (hits, misses) = self.get_hit_stats();
        let total_operations = hits + misses;
        let hit_rate = if total_operations > 0 {
            (hits as f64) / (total_operations as f64) * 100.0
        } else {
            0.0
        };

        MetricsReport {
            hits,
            misses,
            hit_rate,
            total_operations,
            evictions: self.get_evictions(),
            avg_response_time_ms: self.get_avg_response_time_ms(),
            operation_counts: self.get_operation_counts(),
            last_cleanup: self.get_last_cleanup(),
            enabled: self.enabled,
        }
    }
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self::new(true)
    }
}

/// Cache metrics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsReport {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub total_operations: u64,
    pub evictions: u64,
    pub avg_response_time_ms: f64,
    pub operation_counts: HashMap<String, u64>,
    pub last_cleanup: Option<SystemTime>,
    pub enabled: bool,
}

/// Metrics exporter for different formats
pub struct MetricsExporter;

impl MetricsExporter {
    /// Export metrics to JSON
    pub fn to_json(metrics: &MetricsReport) -> Result<String> {
        Ok(serde_json::to_string_pretty(metrics)?)
    }

    /// Export metrics to plain text
    pub fn to_text(metrics: &MetricsReport) -> String {
        format!(
            "Cache Metrics Report\n\
             ====================\n\
             Total Operations: {}\n\
             Cache Hits: {}\n\
             Cache Misses: {}\n\
             Hit Rate: {:.2}%\n\
             Evictions: {}\n\
             Avg Response Time: {:.2}ms\n\
             Last Cleanup: {:?}\n\
             \n\
             Operations by Type:\n\
             {}",
            metrics.total_operations,
            metrics.hits,
            metrics.misses,
            metrics.hit_rate,
            metrics.evictions,
            metrics.avg_response_time_ms,
            metrics.last_cleanup,
            metrics.operation_counts
                .iter()
                .map(|(op, count)| format!("  {}: {}", op, count))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Export metrics to Prometheus format
    pub fn to_prometheus(metrics: &MetricsReport, cache_name: &str) -> String {
        format!(
            "# HELP cache_hits_total Total number of cache hits\n\
             # TYPE cache_hits_total counter\n\
             cache_hits_total{{cache=\"{}\"}} {}\n\
             \n\
             # HELP cache_misses_total Total number of cache misses\n\
             # TYPE cache_misses_total counter\n\
             cache_misses_total{{cache=\"{}\"}} {}\n\
             \n\
             # HELP cache_hit_rate Cache hit rate percentage\n\
             # TYPE cache_hit_rate gauge\n\
             cache_hit_rate{{cache=\"{}\"}} {}\n\
             \n\
             # HELP cache_operations_total Total number of cache operations\n\
             # TYPE cache_operations_total counter\n\
             cache_operations_total{{cache=\"{}\"}} {}\n\
             \n\
             # HELP cache_evictions_total Total number of cache evictions\n\
             # TYPE cache_evictions_total counter\n\
             cache_evictions_total{{cache=\"{}\"}} {}\n",
            cache_name, metrics.hits,
            cache_name, metrics.misses,
            cache_name, metrics.hit_rate,
            cache_name, metrics.total_operations,
            cache_name, metrics.evictions
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_recording() {
        let metrics = CacheMetrics::new(true);

        metrics.record_hit();
        metrics.record_miss();
        metrics.record_operation("get");

        let (hits, misses) = metrics.get_hit_stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);

        let operation_counts = metrics.get_operation_counts();
        assert_eq!(operation_counts["get"], 1);
    }

    #[test]
    fn test_metrics_report() {
        let metrics = CacheMetrics::new(true);

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        let report = metrics.generate_report();

        assert_eq!(report.hits, 2);
        assert_eq!(report.misses, 1);
        assert_eq!(report.total_operations, 3);
        assert!((report.hit_rate - 66.67).abs() < 0.1);
    }

    #[test]
    fn test_metrics_exporter() {
        let metrics = CacheMetrics::new(true);
        metrics.record_hit();
        metrics.record_miss();

        let report = metrics.generate_report();

        let json = MetricsExporter::to_json(&report).unwrap();
        assert!(json.contains("hits"));

        let text = MetricsExporter::to_text(&report);
        assert!(text.contains("Cache Metrics Report"));
        assert!(text.contains("66.67%"));

        let prometheus = MetricsExporter::to_prometheus(&report, "test-cache");
        assert!(prometheus.contains("cache_hits_total"));
        assert!(prometheus.contains("cache_misses_total"));
    }
}
