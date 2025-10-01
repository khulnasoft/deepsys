# Placeholder CMakeLists.txt for CLI
# This will be implemented later
add_executable(deepsys_cli main.cpp)

target_link_libraries(deepsys_cli
    PRIVATE
        deepsys_core
)

# Install executable
install(TARGETS deepsys_cli RUNTIME DESTINATION bin)
install(DIRECTORY include/cli DESTINATION include)
