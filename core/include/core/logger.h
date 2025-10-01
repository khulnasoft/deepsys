#pragma once

#include "core/types.h"
#include <string>
#include <memory>
#include <sstream>

namespace deepsys {
namespace core {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level) { level_ = level; }
    LogLevel level() const { return level_; }

    void log(LogLevel level, const std::string& message);

private:
    Logger() = default;
    ~Logger() = default;

    LogLevel level_ = LogLevel::Info;
};

// Helper macros
#define DEEPSYS_LOG(level, message) \
    do { \
        std::ostringstream oss; \
        oss << message; \
        deepsys::core::Logger::instance().log(level, oss.str()); \
    } while(0)

#define LOG_DEBUG(message) DEEPSYS_LOG(deepsys::core::LogLevel::Debug, message)
#define LOG_INFO(message) DEEPSYS_LOG(deepsys::core::LogLevel::Info, message)
#define LOG_WARNING(message) DEEPSYS_LOG(deepsys::core::LogLevel::Warning, message)
#define LOG_ERROR(message) DEEPSYS_LOG(deepsys::core::LogLevel::Error, message)
#define LOG_CRITICAL(message) DEEPSYS_LOG(deepsys::core::LogLevel::Critical, message)

} // namespace core
} // namespace deepsys
