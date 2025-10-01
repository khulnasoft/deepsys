#pragma once

#include <core/types.h>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <functional>

namespace deepsys {
namespace chisels {

enum class ChiselType {
    Filter,
    Aggregator,
    Formatter,
    Analyzer,
    Generator
};

enum class ChiselState {
    Unloaded,
    Loaded,
    Running,
    Paused,
    Error
};

struct ChiselInfo {
    std::string name;
    std::string version;
    std::string description;
    ChiselType type;
    ChiselState state;
    std::string author;
    std::vector<std::string> tags;
    std::vector<std::string> dependencies;
};

struct ChiselConfig {
    std::string name;
    std::string script_path;
    std::vector<std::string> arguments;
    std::unordered_map<std::string, std::string> parameters;
    bool enable_output = true;
    std::string output_format;
};

struct ChiselOutput {
    std::string data;
    std::string format;
    uint64_t timestamp;
    std::unordered_map<std::string, std::string> metadata;
};

class IChisel {
public:
    virtual ~IChisel() = default;

    // Lifecycle management
    virtual core::Result<void> load(const std::string& path) = 0;
    virtual core::Result<void> unload() = 0;
    virtual core::Result<void> start() = 0;
    virtual core::Result<void> stop() = 0;
    virtual core::Result<void> pause() = 0;
    virtual core::Result<void> resume() = 0;

    // State management
    virtual ChiselState get_state() const = 0;
    virtual core::Result<ChiselInfo> get_info() const = 0;

    // Configuration
    virtual core::Result<void> set_config(const ChiselConfig& config) = 0;
    virtual core::Result<ChiselConfig> get_config() const = 0;
    virtual core::Result<void> set_parameter(const std::string& key, const std::string& value) = 0;
    virtual core::Result<std::string> get_parameter(const std::string& key) const = 0;

    // Execution
    virtual core::Result<ChiselOutput> execute(const std::string& script,
                                              const std::vector<std::string>& args = {}) = 0;
    virtual core::Result<ChiselOutput> execute_file(const std::string& script_path,
                                                   const std::vector<std::string>& args = {}) = 0;

    // Event processing
    virtual core::Result<void> process_event(const core::Event& event) = 0;
    virtual core::Result<std::vector<ChiselOutput>> get_pending_outputs() = 0;
    virtual core::Result<void> flush_outputs() = 0;

    // Output management
    using OutputCallback = std::function<void(const ChiselOutput&)>;
    virtual core::Result<void> set_output_callback(OutputCallback callback) = 0;
    virtual core::Result<void> set_output_format(const std::string& format) = 0;
    virtual core::Result<std::string> get_output_format() const = 0;

    // Error handling
    virtual core::Result<std::string> get_last_error() const = 0;
    virtual core::Result<void> clear_error() = 0;

    // Statistics
    virtual core::Result<uint64_t> get_events_processed() const = 0;
    virtual core::Result<uint64_t> get_outputs_generated() const = 0;
    virtual core::Result<std::unordered_map<std::string, uint64_t>> get_stats() const = 0;
};

class IChiselManager {
public:
    virtual ~IChiselManager() = default;

    // Chisel management
    virtual core::Result<void> load_chisel(const std::string& name, const std::string& path) = 0;
    virtual core::Result<void> unload_chisel(const std::string& name) = 0;
    virtual core::Result<std::vector<ChiselInfo>> list_chisels() const = 0;
    virtual core::Result<ChiselInfo> get_chisel_info(const std::string& name) const = 0;

    // Chisel execution
    virtual core::Result<std::unique_ptr<IChisel>> create_chisel(const std::string& name) = 0;
    virtual core::Result<std::unique_ptr<IChisel>> create_chisel_from_config(const ChiselConfig& config) = 0;

    // Chisel discovery
    virtual core::Result<std::vector<std::string>> discover_chisels(const std::string& directory) = 0;
    virtual core::Result<void> install_chisel(const std::string& name, const std::string& source) = 0;
    virtual core::Result<void> uninstall_chisel(const std::string& name) = 0;

    // Global configuration
    virtual core::Result<void> set_global_parameter(const std::string& key, const std::string& value) = 0;
    virtual core::Result<std::string> get_global_parameter(const std::string& key) const = 0;

    // Event routing
    virtual core::Result<void> route_events_to_chisel(const std::string& chisel_name) = 0;
    virtual core::Result<void> route_events_from_chisel(const std::string& chisel_name,
                                                       std::function<void(const core::Event&)> callback) = 0;
};

} // namespace chisels
} // namespace deepsys
