#pragma once

#include <core/types.h>
#include <vector>
#include <string>
#include <memory>

namespace deepsys {
namespace cli {

enum class OutputFormat {
    Text,
    JSON,
    CSV,
    Table,
    YAML
};

enum class OutputLevel {
    Minimal,
    Standard,
    Verbose,
    Debug
};

struct CLIOptions {
    std::string command;
    std::vector<std::string> arguments;
    OutputFormat format = OutputFormat::Text;
    OutputLevel level = OutputLevel::Standard;
    std::string output_file;
    std::string config_file;
    bool help = false;
    bool version = false;
    bool interactive = false;
    uint32_t timeout_ms = 30000;  // 30 seconds
};

struct CommandInfo {
    std::string name;
    std::string description;
    std::string usage;
    std::vector<std::string> aliases;
    std::vector<std::string> examples;
};

class ICLI {
public:
    virtual ~ICLI() = default;

    // Command execution
    virtual core::Result<int> run(int argc, char** argv) = 0;
    virtual core::Result<int> run_interactive() = 0;

    // Command management
    virtual core::Result<void> register_command(const std::string& name,
                                               std::function<core::Result<int>(const std::vector<std::string>&)> handler,
                                               const std::string& description) = 0;
    virtual core::Result<std::vector<CommandInfo>> get_available_commands() const = 0;

    // Output management
    virtual core::Result<void> set_output_format(OutputFormat format) = 0;
    virtual core::Result<OutputFormat> get_output_format() const = 0;
    virtual core::Result<void> set_output_level(OutputLevel level) = 0;
    virtual core::Result<OutputLevel> get_output_level() const = 0;

    // Configuration
    virtual core::Result<void> load_config(const std::string& config_file) = 0;
    virtual core::Result<void> save_config(const std::string& config_file) const = 0;
    virtual core::Result<void> set_option(const std::string& key, const std::string& value) = 0;
    virtual core::Result<std::string> get_option(const std::string& key) const = 0;

    // Input/Output
    virtual core::Result<void> print(const std::string& message, OutputLevel level = OutputLevel::Standard) = 0;
    virtual core::Result<void> print_error(const std::string& message) = 0;
    virtual core::Result<void> print_warning(const std::string& message) = 0;
    virtual core::Result<void> print_debug(const std::string& message) = 0;

    // Interactive features
    virtual core::Result<std::string> prompt(const std::string& message) = 0;
    virtual core::Result<bool> confirm(const std::string& message) = 0;

    // Help and documentation
    virtual core::Result<std::string> get_help() const = 0;
    virtual core::Result<std::string> get_command_help(const std::string& command) const = 0;
    virtual core::Result<std::string> get_version() const = 0;

    // Event handling
    virtual core::Result<void> set_event_handler(std::function<void(const core::Event&)> handler) = 0;
    virtual core::Result<void> process_events() = 0;
};

} // namespace cli
} // namespace deepsys
