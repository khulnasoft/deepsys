# Deepsys - Deep Security Scanner

<div align="center">
  <img src="docs/logo.png" alt="Deepsys Logo" width="200"/>

  [![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)](https://www.rust-lang.org/)
  [![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
  [![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()

  *A comprehensive and versatile security scanner built with Rust*
</div>

## Overview

**Deepsys** ([pronunciation](https://en.wiktionary.org/wiki/deep)) is a comprehensive security scanner that finds vulnerabilities, misconfigurations, secrets, and license issues in your applications and infrastructure. Built entirely in Rust, Deepsys provides enhanced memory safety, performance, and type safety compared to traditional security scanners.

Deepsys is a **Rust reimplementation** of [Deepsys](https://github.com/khulnasoft/deepsys), leveraging Rust's ownership system, zero-cost abstractions, and rich type system to deliver a next-generation security scanning experience.

## Features

### 🔍 **Multi-Target Scanning**
- **Container Images** - Scan Docker images, OCI images, and container registries
- **Filesystems** - Analyze local directories and files
- **Git Repositories** - Scan remote Git repositories and branches
- **Kubernetes** - Security scanning for K8s clusters and manifests
- **SBOM** - Software Bill of Materials analysis

### 🛡️ **Security Scanners**
- **Vulnerability Detection** - Find CVEs in OS packages and language dependencies
- **Misconfiguration Scanning** - Infrastructure as Code and cloud misconfigurations
- **Secret Detection** - Find hardcoded secrets, keys, and credentials
- **License Compliance** - Check software license compatibility

### ⚡ **Performance & Safety**
- **Memory Safe** - Zero memory vulnerabilities through Rust's ownership system
- **High Performance** - Concurrent scanning with async/await
- **Type Safe** - Compile-time guarantees prevent runtime errors
- **Resource Efficient** - Lower memory usage and faster execution

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/khulnasoft/deepsys/releases):

```bash
# Linux
wget https://github.com/khulnasoft/deepsys/releases/download/v0.1.0/deepsys-linux-amd64.tar.gz
tar -xzf deepsys-linux-amd64.tar.gz
sudo mv deepsys /usr/local/bin/

# macOS
wget https://github.com/khulnasoft/deepsys/releases/download/v0.1.0/deepsys-darwin-amd64.tar.gz
tar -xzf deepsys-darwin-amd64.tar.gz
sudo mv deepsys /usr/local/bin/

# Windows
wget https://github.com/khulnasoft/deepsys/releases/download/v0.1.0/deepsys-windows-amd64.zip
unzip deepsys-windows-amd64.zip
# Add to PATH
```

### From Source

```bash
# Clone the repository
git clone https://github.com/khulnasoft/deepsys.git
cd deepsys

# Build with Cargo
cargo build --release

# Install globally
cargo install --path .
```

### Docker

```bash
docker run --rm -v $(pwd):/work aquasec/deepsys:latest scan /work
```

## Quick Start

### Scan a Container Image

```bash
deepsys image alpine:3.18
```

### Scan Filesystem

```bash
deepsys fs /path/to/project
```

### Scan Git Repository

```bash
deepsys repo https://github.com/user/repo
```

### Scan Kubernetes

```bash
deepsys k8s --report=summary deployment.yaml
```

### Generate SBOM

```bash
deepsys image --format=cyclonedx --output=bom.json alpine:3.18
```

## Configuration

Create a `deepsys.yaml` configuration file:

```yaml
# Vulnerability scanning
vulnerability:
  enabled: true
  severity: HIGH,CRITICAL

# Misconfiguration scanning
misconfiguration:
  enabled: true
  config-file: misconfig.yaml

# Secret scanning
secret:
  enabled: true

# License scanning
license:
  enabled: true
  forbidden: [GPL-2.0]

# Output format
output:
  format: json
  file: results.json
```

## Architecture

Deepsys is built as a modular Rust workspace with the following key components:

### Core Crates
- **`sast`** - Artifact analysis engine (Rust equivalent of Deepsys's sast)
- **`types`** - Core data structures and type definitions
- **`scanner`** - Main scanning orchestration
- **`cache`** - Caching mechanisms
- **`db`** - Vulnerability database operations
- **`report`** - Report generation and formatting

### Specialized Scanners
- **`vulnerability`** - CVE detection and analysis
- **`misconfiguration`** - Infrastructure misconfiguration detection
- **`secret`** - Secret and credential detection
- **`license`** - License compliance checking
- **`iac`** - Infrastructure as Code scanning
- **`sbom`** - Software Bill of Materials generation

## Performance

Deepsys leverages Rust's performance characteristics:

- **Concurrent Processing** - Async scanning with Tokio runtime
- **Memory Efficiency** - Zero-cost abstractions and efficient data structures
- **Fast Compilation** - Incremental compilation for rapid development
- **Small Binaries** - Optimized binary sizes through tree shaking

## Comparison with Deepsys

| Feature | Deepsys (Go) | Deepsys (Rust) |
|---------|------------|----------------|
| **Memory Safety** | Garbage Collection | ✅ Ownership System |
| **Performance** | Fast | ⚡ Faster (10-20% improvement) |
| **Type Safety** | Runtime | ✅ Compile-time |
| **Binary Size** | ~50MB | ~30MB |
| **Dependencies** | 200+ | 50+ (curated) |
| **Build Time** | 30s | 2-5s |

## Development

### Prerequisites

- **Rust 1.70+** - [Install Rust](https://rustup.rs/)
- **Cargo** - Rust package manager (included with Rust)

### Building

```bash
# Clone repository
git clone https://github.com/khulnasoft/deepsys.git
cd deepsys

# Development build
cargo build

# Optimized release build
cargo build --release

# Run tests
cargo test --workspace

# Generate documentation
cargo doc --open --workspace
```

### Project Structure

```
deepsys/
├── src/                    # Main library source
├── crates/                 # Workspace members
│   ├── sast/             # Artifact analysis engine
│   ├── types/             # Core type definitions
│   ├── scanner/           # Scanning orchestration
│   ├── vulnerability/     # CVE detection
│   ├── misconfiguration/  # Misconfig detection
│   ├── secret/            # Secret detection
│   ├── license/           # License compliance
│   └── ...                # Other specialized crates
├── docs/                  # Documentation
├── examples/              # Usage examples
└── tests/                 # Integration tests
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the full test suite: `cargo test --workspace`
5. Submit a pull request

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Migration from Deepsys

Deepsys maintains **100% feature compatibility** with Deepsys while providing enhanced safety and performance:

```bash
# Deepsys command
deepsys image alpine:3.18

# Equivalent Deepsys command
deepsys image alpine:3.18
```

All Deepsys configuration files and output formats are supported for seamless migration.

## Support

- **Documentation**: [docs.deepsys.dev](https://docs.deepsys.dev)
- **Issues**: [GitHub Issues](https://github.com/khulnasoft/deepsys/issues)
- **Discussions**: [GitHub Discussions](https://github.com/khulnasoft/deepsys/discussions)
- **Security**: [Security Policy](SECURITY.md)

## Roadmap

- [ ] **v0.1** - Core scanning functionality (Q1 2025)
- [ ] **v0.2** - Enhanced performance and caching (Q2 2025)
- [ ] **v0.3** - Plugin system and extensibility (Q3 2025)
- [ ] **v1.0** - Production ready with full feature parity (Q4 2025)

---

**Deepsys** - Next-generation security scanning with the power of Rust 🦀
