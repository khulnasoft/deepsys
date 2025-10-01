#include <gtest/gtest.h>
#include <core/logger.h>
#include <core/types.h>

using namespace deepsys::core;

TEST(CoreTest, LoggerTest) {
    Logger::instance().set_level(LogLevel::Debug);

    // These should all appear in the output
    LOG_DEBUG("This is a debug message");
    LOG_INFO("This is an info message");
    LOG_WARNING("This is a warning message");

    // Test error code
    auto ec = make_error_code(ErrorCode::InvalidArgument);
    EXPECT_EQ(ec, ErrorCode::InvalidArgument);
    EXPECT_EQ(ec.message(), "Invalid argument");
}

TEST(CoreTest, ResultTest) {
    Result<int> success_result(42);
    EXPECT_TRUE(success_result);
    EXPECT_EQ(success_result.value(), 42);

    Result<int> error_result(ErrorCode::NotFound);
    EXPECT_FALSE(error_result);
    EXPECT_EQ(error_result.error(), ErrorCode::NotFound);
}
