# Placeholder CMakeLists.txt for libsinsp
# This will be implemented later
add_library(deepsys_libsinsp INTERFACE)

target_include_directories(deepsys_libsinsp
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Install headers
install(DIRECTORY include/sinsp DESTINATION include)
