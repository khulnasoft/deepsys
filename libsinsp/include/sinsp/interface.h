#pragma once

#include <core/types.h>
#include <vector>
#include <memory>
#include <string>
#include <unordered_map>

namespace deepsys {
namespace sinsp {

enum class FilterCheckType {
    Process,
    Thread,
    FileDescriptor,
    Network,
    Memory,
    System,
    Event,
    Time
};

struct FilterCheckInfo {
    std::string name;
    FilterCheckType type;
    std::string description;
    std::vector<std::string> tags;
    std::vector<std::string> examples;
};

struct ProcessInfo {
    core::ProcessID pid;
    core::ThreadID tid;
    std::string exe;
    std::string args;
    std::string cwd;
    uint64_t start_time;
    std::string user;
    std::string group;
    std::unordered_map<std::string, std::string> env;
    std::vector<std::string> open_fds;
};

struct EventDescription {
    std::string name;
    std::string category;
    std::string description;
    std::vector<std::string> parameters;
    std::vector<std::string> examples;
};

class IInspector {
public:
    virtual ~IInspector() = default;

    // Event inspection
    virtual core::Result<void> inspect_event(const core::Event& event) = 0;
    virtual core::Result<EventDescription> get_event_description(core::EventID event_id) const = 0;
    virtual core::Result<std::vector<EventDescription>> get_all_event_descriptions() const = 0;

    // Process tracking
    virtual core::Result<ProcessInfo> get_process_info(core::ProcessID pid) const = 0;
    virtual core::Result<std::vector<ProcessInfo>> get_all_processes() const = 0;
    virtual core::Result<std::vector<ProcessInfo>> get_child_processes(core::ProcessID parent_pid) const = 0;

    // Thread tracking
    virtual core::Result<ProcessInfo> get_thread_info(core::ThreadID tid) const = 0;
    virtual core::Result<std::vector<ProcessInfo>> get_all_threads() const = 0;

    // File descriptor tracking
    virtual core::Result<std::vector<std::string>> get_process_fds(core::ProcessID pid) const = 0;
    virtual core::Result<std::string> get_fd_info(core::FileDescriptor fd) const = 0;

    // Network tracking
    virtual core::Result<std::vector<std::string>> get_network_connections(core::ProcessID pid) const = 0;
    virtual core::Result<std::string> get_connection_info(const std::string& connection_id) const = 0;

    // Memory tracking
    virtual core::Result<uint64_t> get_process_memory_usage(core::ProcessID pid) const = 0;
    virtual core::Result<std::unordered_map<std::string, uint64_t>> get_system_memory_info() const = 0;

    // Filtering
    virtual core::Result<void> set_filter(const std::string& filter) = 0;
    virtual core::Result<std::string> get_filter() const = 0;
    virtual core::Result<bool> matches_filter(const core::Event& event) const = 0;

    // Filter checks
    virtual core::Result<std::vector<FilterCheckInfo>> get_available_filter_checks() const = 0;
    virtual core::Result<FilterCheckInfo> get_filter_check_info(const std::string& check_name) const = 0;

    // Event formatting
    virtual core::Result<std::string> format_event_as_text(const core::Event& event) const = 0;
    virtual core::Result<std::string> format_event_as_json(const core::Event& event) const = 0;

    // Statistics
    virtual core::Result<std::unordered_map<std::string, uint64_t>> get_stats() const = 0;
    virtual core::Result<uint64_t> get_stat(const std::string& stat_name) const = 0;
};

} // namespace sinsp
} // namespace deepsys
