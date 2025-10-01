#include "core/types.h"

namespace deepsys {
namespace core {

std::string ErrorCategory::message(int ev) const {
    switch (static_cast<ErrorCode>(ev)) {
        case ErrorCode::Success: return "Success";
        case ErrorCode::InvalidArgument: return "Invalid argument";
        case ErrorCode::SystemError: return "System error";
        case ErrorCode::NotImplemented: return "Not implemented";
        case ErrorCode::NotFound: return "Not found";
        case ErrorCode::AlreadyExists: return "Already exists";
        case ErrorCode::PermissionDenied: return "Permission denied";
        case ErrorCode::ResourceExhausted: return "Resource exhausted";
        case ErrorCode::InvalidOperation: return "Invalid operation";
        case ErrorCode::InternalError: return "Internal error";
        default: return "Unknown error";
    }
}

std::error_code make_error_code(ErrorCode e) {
    static ErrorCategory category;
    return {static_cast<int>(e), category};
}

std::error_condition make_error_condition(ErrorCode e) {
    static ErrorCategory category;
    return {static_cast<int>(e), category};
}

} // namespace core
} // namespace deepsys
