# Core library
add_library(deepsys_core
    src/types.cpp
    src/logger.cpp
)

target_include_directories(deepsys_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Add compiler warnings
if(MSVC)
    target_compile_options(deepsys_core PRIVATE /W4 /WX)
else()
    target_compile_options(deepsys_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Install headers
install(DIRECTORY include/core DESTINATION include)
