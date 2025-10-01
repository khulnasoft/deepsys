#pragma once

#include <core/types.h>
#include <vector>
#include <memory>
#include <string>
#include <functional>

namespace deepsys {
namespace scap {

enum class CaptureMode {
    Live,
    File,
    Memory
};

enum class EventFormat {
    Binary,
    Text,
    JSON
};

struct CaptureConfig {
    CaptureMode mode = CaptureMode::Live;
    std::string source;  // Device path or file path
    uint32_t buffer_size = 8192;
    bool enable_drop_capture = false;
    std::vector<std::string> enabled_events;
};

struct SystemInfo {
    std::string machine_id;
    std::string boot_id;
    uint32_t num_cpus;
    uint64_t memory_size;
    std::string kernel_version;
    std::string os_release;
};

class IScapEngine {
public:
    virtual ~IScapEngine() = default;

    // Lifecycle management
    virtual core::Result<void> open() = 0;
    virtual core::Result<void> close() = 0;
    virtual bool is_open() const = 0;

    // Configuration
    virtual core::Result<void> set_config(const CaptureConfig& config) = 0;
    virtual core::Result<CaptureConfig> get_config() const = 0;

    // Event capture
    virtual core::Result<std::vector<core::Event>> capture_next_batch(uint32_t timeout_ms = 1000) = 0;
    virtual core::Result<std::vector<core::Event>> capture_all() = 0;

    // System information
    virtual core::Result<SystemInfo> get_system_info() const = 0;
    virtual core::Result<uint64_t> get_stats(const std::string& stat_name) const = 0;

    // Event filtering
    virtual core::Result<void> set_event_filter(const std::string& filter) = 0;
    virtual core::Result<std::string> get_event_filter() const = 0;

    // PPM (Process Performance Monitoring) specific
    virtual core::Result<void> enable_ppm_sc() = 0;
    virtual core::Result<void> disable_ppm_sc() = 0;
    virtual core::Result<std::vector<uint32_t>> get_enabled_sc() const = 0;

    // Buffer management
    virtual core::Result<void> set_snaplen(uint32_t snaplen) = 0;
    virtual core::Result<uint32_t> get_snaplen() const = 0;

    // Event processing callbacks
    using EventCallback = std::function<void(const core::Event&)>;
    virtual core::Result<void> set_event_callback(EventCallback callback) = 0;
};

} // namespace scap
} // namespace deepsys
