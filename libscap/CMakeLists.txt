# Placeholder CMakeLists.txt for libscap
# This will be implemented later
add_library(deepsys_libscap INTERFACE)

target_include_directories(deepsys_libscap
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Install headers
install(DIRECTORY include/scap DESTINATION include)
