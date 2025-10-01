cmake_minimum_required(VERSION 3.15)
project(deepsys VERSION 0.1.0 LANGUAGES C CXX)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(BUILD_TESTS "Build tests" ON)
option(BUILD_DRIVER "Build kernel driver" ON)
option(BUILD_TOOLS "Build additional tools" ON)

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add subdirectories
add_subdirectory(core)

if(BUILD_DRIVER)
    add_subdirectory(driver)
endif()

add_subdirectory(libscap)
add_subdirectory(libsinsp)
add_subdirectory(cli)
add_subdirectory(chisels)

# Example usage of the modular architecture
add_executable(deepsys_example example_usage.cpp)
add_executable(deepsys_simple_test simple_test.cpp)

target_link_libraries(deepsys_example
    PRIVATE
        deepsys_core
)

target_link_libraries(deepsys_simple_test
    PRIVATE
        deepsys_core
)

target_include_directories(deepsys_example
    PRIVATE
        driver/include
        libscap/include
        libsinsp/include
)

if(BUILD_TESTS)
    # Try to find GTest, but don't fail if not found
    find_package(GTest QUIET)
    if(GTest_FOUND)
        enable_testing()
        add_subdirectory(tests)
    else()
        message(WARNING "GTest not found - tests will not be built")
    endif()
endif()

# Installation
install(DIRECTORY include/ DESTINATION include)
install(TARGETS deepsys_core
              deepsys_libscap
              deepsys_libsinsp
              deepsys_cli
              deepsys_example
              deepsys_simple_test
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
