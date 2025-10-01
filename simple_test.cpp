#include <iostream>
#include <string>
#include <core/types.h>

using namespace deepsys::core;

int main() {
    std::cout << "Testing basic core functionality" << std::endl;

    // Test basic types
    EventID id = 123;
    ProcessID pid = 456;
    std::cout << "Event ID: " << id << ", Process ID: " << pid << std::endl;

    // Test error handling
    auto ec = make_error_code(ErrorCode::InvalidArgument);
    std::cout << "Error code value: " << static_cast<int>(ec.value()) << std::endl;

    // Test Result class
    Result<int> success_result(42);
    if (success_result) {
        std::cout << "Success result: " << success_result.value() << std::endl;
    }

    Result<int> error_result(ErrorCode::NotFound);
    if (!error_result) {
        std::cout << "Error result: " << static_cast<int>(error_result.error()) << std::endl;
    }

    std::cout << "Basic test completed successfully" << std::endl;
    return 0;
}
