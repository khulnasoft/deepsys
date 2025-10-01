#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <system_error>

namespace deepsys {
namespace core {

// Basic types
using EventID = uint32_t;
using ProcessID = int32_t;
using ThreadID = int64_t;
using FileDescriptor = int32_t;
using Timestamp = uint64_t;

// Error handling
enum class ErrorCode {
    Success = 0,
    InvalidArgument,
    SystemError,
    NotImplemented,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    InvalidOperation,
    InternalError
};

class ErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override { return "deepsys"; }
    std::string message(int ev) const override;
};

std::error_code make_error_code(ErrorCode e);
std::error_condition make_error_condition(ErrorCode e);

// Common result type
template<typename T>
class Result {
public:
    Result() : error_(ErrorCode::Success) {}
    Result(T value) : value_(std::move(value)), error_(ErrorCode::Success) {}
    Result(ErrorCode ec) : error_(ec) {}

    bool ok() const { return error_ == ErrorCode::Success; }
    explicit operator bool() const { return ok(); }

    T& value() & { return value_; }
    const T& value() const & { return value_; }
    T&& value() && { return std::move(value_); }

    ErrorCode error() const { return error_; }

private:
    T value_{};
    ErrorCode error_ = ErrorCode::Success;
};

// Common event structure
struct Event {
    EventID id{0};
    Timestamp timestamp{0};
    ProcessID pid{0};
    ThreadID tid{0};
    // Add more common fields as needed
};

} // namespace core
} // namespace deepsys

namespace std {
template <>
struct is_error_code_enum<deepsys::core::ErrorCode> : true_type {};
} // namespace std
