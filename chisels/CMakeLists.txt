# Placeholder CMakeLists.txt for chisels
# This will be implemented later
add_library(deepsys_chisels INTERFACE)

target_include_directories(deepsys_chisels
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Install headers
install(DIRECTORY include/chisels DESTINATION include)
