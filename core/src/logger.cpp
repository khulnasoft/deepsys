#include "core/logger.h"
#include <iostream>

namespace deepsys {
namespace core {

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < level_) {
        return;
    }

    const char* level_str = "";
    switch (level) {
        case LogLevel::Debug:    level_str = "DEBUG"; break;
        case LogLevel::Info:     level_str = "INFO"; break;
        case LogLevel::Warning:  level_str = "WARNING"; break;
        case LogLevel::Error:    level_str = "ERROR"; break;
        case LogLevel::Critical: level_str = "CRITICAL"; break;
    }

    std::cerr << "[" << level_str << "] " << message << std::endl;
}

} // namespace core
} // namespace deepsys
