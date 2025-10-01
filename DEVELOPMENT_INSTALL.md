# DeepSys Modular Architecture - Development Installation Guide

## Overview

The DeepSys modular architecture consists of several independent components that can be built and installed separately. This guide covers development installation from source code.

## Prerequisites

### System Requirements
- Linux (Ubuntu 16.04+, CentOS 7+, or similar)
- Kernel headers (for driver module)
- Build tools: gcc, g++, make, cmake
- Development libraries: pkg-config, git

### Installing Prerequisites

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config git
sudo apt-get install linux-headers-$(uname -r)
```

#### CentOS/RHEL:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install cmake pkgconfig git
sudo yum install kernel-devel-$(uname -r)
```

## Building from Source

### 1. Clone the Repository
```bash
git clone https://github.com/khulnasoft/deepsys.git
cd deepsys
```

### 2. Create Build Directory
```bash
mkdir build && cd build
```

### 3. Configure Build
```bash
# For release build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local ..

# For debug build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/usr/local ..

# Build with tests (requires GTest)
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
```

### 4. Build Components
```bash
# Build all components
make -j$(nproc)

# Build specific modules
make deepsys_core       # Core utilities
make deepsys_libscap    # System call capture
make deepsys_libsinsp   # System state inspection
make deepsys_cli        # Command-line interface
make deepsys_chisels    # Chisel framework
```

### 5. Install Components
```bash
# Install all components
sudo make install

# Install specific modules
sudo make install_core
sudo make install_libscap
sudo make install_libsinsp
sudo make install_cli
sudo make install_chisels
```

## Module Dependencies

The modules have the following dependencies:

```
cli ──┐
      ├── libsinsp ──┐
      │             ├── libscap ──┐
      │             │            ├── driver
      │             │            └── core
      │             └── core
      └── chisels ───┴── core
```

### Building Individual Modules

#### Core Module Only:
```bash
mkdir build_core && cd build_core
cmake -DCMAKE_BUILD_TYPE=Release ../core
make && sudo make install
```

#### LibSCAP with Dependencies:
```bash
mkdir build_libscap && cd build_libscap
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_DRIVER=ON ../
make deepsys_core deepsys_libscap
sudo make install_core install_libscap
```

## Development Workflow

### Using the Build System
```bash
# Clean build
make clean

# Rebuild specific module
make deepsys_cli

# Run tests (if GTest is available)
make test

# Install headers for development
sudo make install_headers
```

### Including Headers in Your Code
```cpp
#include <core/types.h>
#include <scap/interface.h>
#include <sinsp/interface.h>
```

### Linking with Libraries
```cmake
find_package(deepsys_core REQUIRED)
find_package(deepsys_libscap REQUIRED)
find_package(deepsys_libsinsp REQUIRED)

target_link_libraries(your_app
    deepsys::core
    deepsys::libscap
    deepsys::libsinsp
)
```

## Troubleshooting

### Common Issues

#### Missing Kernel Headers
```bash
# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r)

# CentOS/RHEL
sudo yum install kernel-devel-$(uname -r)
```

#### CMake Configuration Issues
```bash
# Clear CMake cache
rm -rf build/
mkdir build && cd build
cmake ..
```

#### Driver Module Issues
```bash
# Check if DKMS is installed
sudo yum install dkms  # RHEL/CentOS
sudo apt-get install dkms  # Ubuntu/Debian

# Manual driver build
cd driver/
make
sudo make install
```

### Getting Help

- Check the build output for error messages
- Verify all dependencies are installed
- Ensure you're using a supported kernel version
- Check the DeepSys documentation for platform-specific notes

## Advanced Configuration

### Custom Installation Prefix
```bash
cmake -DCMAKE_INSTALL_PREFIX=/opt/deepsys ..
```

### Building with Clang
```bash
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
```

### Static Linking
```bash
cmake -DBUILD_SHARED_LIBS=OFF ..
```

### Debug Symbols
```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
```
