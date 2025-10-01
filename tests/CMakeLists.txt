# Find GTest
find_package(GTest REQUIRED)
include(GoogleTest)

# Add test executable
add_executable(core_tests
    core/test_core.cpp
)

# Link with core library and GTest
target_link_libraries(core_tests
    PRIVATE
        deepsys_core
        GTest::GTest
        GTest::Main
)

# Add test
gtest_discover_tests(core_tests)
