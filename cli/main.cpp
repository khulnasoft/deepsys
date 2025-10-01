#include <iostream>
#include <core/logger.h>

using namespace deepsys::core;

int main(int argc, char** argv) {
    LOG_INFO("DeepSys CLI - Placeholder implementation");

    if (argc > 1) {
        LOG_INFO("Arguments provided:");
        for (int i = 1; i < argc; ++i) {
            LOG_INFO("  " << argv[i]);
        }
    } else {
        LOG_INFO("No arguments provided");
    }

    return 0;
}
