# DeepSys - Modular System Monitoring Tool

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)]()

DeepSys is a modular system monitoring and troubleshooting tool that provides deep visibility into system behavior. The modular architecture allows for flexible deployment and development.

## 🏗️ Architecture Overview

DeepSys is built with a modular architecture consisting of independent components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        DeepSys CLI                              │
├─────────────────────────────────────────────────────────────────┤
│  Command-line interface for system monitoring and analysis     │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                     Chisel Framework                           │
├─────────────────────────────────────────────────────────────────┤
│  Lua scripting framework for custom analysis and formatting     │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                   System State Inspector                       │
├─────────────────────────────────────────────────────────────────┤
│  libsinsp - Real-time system state tracking and filtering      │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                  System Call Capture                           │
├─────────────────────────────────────────────────────────────────┤
│  libscap - Low-level system call interception and buffering    │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                         Core Library                           │
├─────────────────────────────────────────────────────────────────┤
│  Core utilities, types, error handling, and logging            │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                       Kernel Driver                            │
├─────────────────────────────────────────────────────────────────┤
│  Kernel module for system call interception                    │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Installation

#### Using Package Manager (Recommended)
```bash
# Ubuntu/Debian
sudo apt-get install deepsys-cli deepsys-core

# CentOS/RHEL
sudo yum install deepsys-cli deepsys-core
```

#### Building from Source
```bash
git clone https://github.com/khulnasoft/deepsys.git
cd deepsys
./scripts/build-modular.sh -t Release -i
```

### Basic Usage

```bash
# Start system monitoring
deepsys_cli

# Capture system calls for 30 seconds
deepsys_cli -t 30s

# Filter events by process name
deepsys_cli -f "proc.name contains firefox"

# Output in JSON format
deepsys_cli -o json
```

## 📦 Installation Options

### Modular Installation

Install only the components you need:

```bash
# Install only CLI and core
sudo ./scripts/install-deepsys-modular -c core,cli

# Install for development
sudo ./scripts/install-deepsys-modular --mode development

# Install from source
./scripts/build-modular.sh -t Release -m core,cli -i
```

### Available Modules

| Module | Description | Runtime | Development |
|--------|-------------|---------|-------------|
| **core** | Core utilities and types | ✓ | ✓ |
| **driver** | Kernel driver for syscall interception | ✓ | - |
| **libscap** | System call capture library | ✓ | ✓ |
| **libsinsp** | System state inspection | ✓ | ✓ |
| **cli** | Command-line interface | ✓ | - |
| **chisels** | Lua scripting framework | ✓ | - |

## 🛠️ Development

### Building Individual Modules

```bash
# Build only core module
./scripts/build-modular.sh -m core

# Build multiple modules
./scripts/build-modular.sh -m core,libscap,cli

# Debug build with tests
./scripts/build-modular.sh -t Debug --test
```

### Module Dependencies

```
cli ──┐
      ├── libsinsp ──┐
      │             ├── libscap ──┐
      │             │            ├── driver
      │             │            └── core
      │             └── core
      └── chisels ───┴── core
```

### Using in Your Code

```cpp
#include <core/types.h>
#include <scap/interface.h>
#include <sinsp/interface.h>

int main() {
    // Use DeepSys components
    deepsys::core::Logger::instance().log(
        deepsys::core::LogLevel::Info,
        "Hello DeepSys!"
    );
    return 0;
}
```

## 🔧 Configuration

### Module Configuration

Each module can be configured independently:

```bash
# Configure system call capture
deepsys_cli --scap-config buffer_size=8192

# Configure event filtering
deepsys_cli --filter "evt.type = execve"

# Configure output format
deepsys_cli --output-format json
```

### Environment Variables

- `DEEPSYS_CONFIG_DIR`: Directory for configuration files (default: `/etc/deepsys`)
- `DEEPSYS_LOG_LEVEL`: Logging level (default: `info`)
- `DEEPSYS_BUFFER_SIZE`: Event buffer size (default: `8192`)

## 📊 Chisel Scripts

DeepSys includes a powerful Lua scripting framework for custom analysis:

```lua
-- Example chisel script
description = "Process execution summary"
category = "Process"

function on_init()
    processes = {}
end

function on_capture(evt)
    if evt.type == "execve" then
        local proc = evt.proc
        if not processes[proc.pid] then
            processes[proc.pid] = {
                name = proc.name,
                count = 0
            }
        end
        processes[proc.pid].count = processes[proc.pid].count + 1
    end
end

function on_stop()
    for pid, proc in pairs(processes) do
        print(string.format("%d: %s (%d executions)",
              pid, proc.name, proc.count))
    end
end
```

## 🧪 Testing

### Running Tests

```bash
# Build and run all tests
./scripts/build-modular.sh --test

# Run specific module tests
ctest -R core

# Run with verbose output
ctest --output-on-failure -V
```

### Writing Tests

```cpp
#include <gtest/gtest.h>
#include <core/types.h>

TEST(CoreTest, ResultSuccess) {
    deepsys::core::Result<int> result(42);
    EXPECT_TRUE(result);
    EXPECT_EQ(result.value(), 42);
}
```

## 📚 API Reference

### Core Types

```cpp
namespace deepsys::core {

// Basic types
using EventID = uint32_t;
using ProcessID = int32_t;
using ThreadID = int64_t;

// Error handling
enum class ErrorCode {
    Success, InvalidArgument, SystemError, NotImplemented
};

// Result type
template<typename T>
class Result {
    bool ok() const;
    T& value();
    ErrorCode error() const;
};

// Logging
enum class LogLevel { Debug, Info, Warning, Error, Critical };
class Logger {
    static Logger& instance();
    void log(LogLevel level, const std::string& message);
};

} // namespace deepsys::core
```

### System Call Capture (libscap)

```cpp
namespace deepsys::scap {

class IScapEngine {
    virtual Result<void> open() = 0;
    virtual Result<std::vector<Event>> capture_next_batch() = 0;
    virtual Result<SystemInfo> get_system_info() const = 0;
};

} // namespace deepsys::scap
```

### System State Inspection (libsinsp)

```cpp
namespace deepsys::sinsp {

class IInspector {
    virtual Result<void> inspect_event(const Event& event) = 0;
    virtual Result<ProcessInfo> get_process_info(ProcessID pid) = 0;
    virtual Result<void> set_filter(const std::string& filter) = 0;
};

} // namespace deepsys::sinsp
```

## 🔒 Security

DeepSys follows security best practices:

- **Minimal privileges**: Modules run with minimal required permissions
- **Secure defaults**: Conservative default settings
- **Input validation**: All inputs are validated and sanitized
- **Error handling**: Secure error handling prevents information leakage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `./scripts/build-modular.sh --test`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Development Guidelines

- **Code style**: Follow the project's coding conventions
- **Tests**: Add tests for all new functionality
- **Documentation**: Update documentation for API changes
- **Modular design**: Maintain clear separation between modules

## 📄 License

DeepSys is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Built on the foundation of sysdig
- Thanks to the open source community for contributions
- Special thanks to early adopters and contributors

## 📞 Support

- **Documentation**: [docs.deepsys.io](https://docs.deepsys.io)
- **Community**: [community.deepsys.io](https://community.deepsys.io)
- **Issues**: [github.com/khulnasoft/deepsys/issues](https://github.com/khulnasoft/deepsys/issues)
- **Mailing List**: [groups.google.com/forum/#!forum/deepsys](https://groups.google.com/forum/#!forum/deepsys)

---

**Happy Monitoring!** 🕵️‍♂️
