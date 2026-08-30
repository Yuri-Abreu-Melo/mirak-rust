# MIRAK: RPKI Validator Vulnerability Scanner

![MIRAK](./assets/media/mirak-crest.jpeg)

<div align="center">

[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![Rust](https://img.shields.io/badge/Rust-CE422B?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Routinator](https://img.shields.io/badge/Routinator-4A90E2?style=for-the-badge)](https://www.nlnetlabs.nl/projects/routinator/about/)
[![IEEE Access](https://img.shields.io/badge/IEEE%20Access-00629B?style=for-the-badge)](https://ieeeaccess.ieee.org/)

</div>

## Demo

https://github.com/user-attachments/assets/8904ca7d-f940-4b30-826c-460edfaf885e

## Overview

This repository contains MIRAK, a Rust-based vulnerability scanner designed to audit RPKI (Resource Public Key Infrastructure) validator implementations, such as Routinator. The artifact provides non-intrusive security auditing capabilities for RPKI validator deployments, enabling security researchers and network administrators to identify vulnerabilities in deployed validator software.

The associated paper, *"MIRAK: Enhancing Security and Resilience in RPKI and BGP Routing Ecosystems"*, presents an approach for predictive vulnerability auditing of RPKI validation environments. By integrating domain-specific knowledge of the RPKI ecosystem, MIRAK addresses limitations found in traditional vulnerability scanners, which may fail to accurately identify vulnerabilities in RPKI-specific components due to inaccuracies in the generation and mapping of **CPE (Common Platform Enumeration)** identifiers. The artifact is intended to enable researchers and operators to audit RPKI validator deployments, identify applicable **CVEs (Common Vulnerabilities and Exposures)**, and evaluate the security of critical routing infrastructure through an automated and reproducible workflow.

### Paper Abstract

*RPKI (Resource Public Key Infrastructure) has become the standard mechanism for mitigating BGP (Border Gateway Protocol) prefix hijacking in the global interdomain routing infrastructure. However, the security of the validation infrastructure itself, particularly RPKI Relying Party implementations, has emerged as a critical attack surface, where unidentified vulnerabilities may compromise the integrity of the routing ecosystem. This paper presents MIRAK, a predictive auditing artifact designed to non-intrusively identify vulnerabilities in RPKI validation environments and detect software components susceptible to exploitation. By incorporating domain-specific knowledge, the artifact overcomes limitations of traditional vulnerability scanners that fail to accurately map components of the RPKI ecosystem due to inaccuracies in CPE (Common Platform Enumeration) string generation. Experimental evaluations conducted on real-world scenarios based on the Routinator validator demonstrate the effectiveness of the approach compared with Vuls, Trivy, and Grype, achieving a 100% higher detection rate in identifying applicable CVEs.*

## Requirements

MIRAK requires the following system dependencies to function properly:

### Operating System
MIRAK is tested and compatible with:
- **Ubuntu 22.04 LTS** (Jammy)
- **Debian 12** (Bookworm)
- **Fedora 43**

### System Specifications
- Minimum 2GB RAM
- 2 CPU cores
- x86_64 Linux architecture

### Build Dependencies

#### Rust Build Environment Setup

```
rustup target add x86_64-unknown-linux-musl
```

#### musl (Ubuntu/Debian)

```
sudo apt install musl-tools
```

#### musl (Fedora)

```
sudo dnf install musl-gcc
```

#### musl (Arch Linux)

```
sudo pacman -S musl
```

#### GTK4 Development Libraries (for GUI builds)

**GTK4 (Ubuntu/Debian):**

```
sudo apt install libgtk-4-dev pkg-config
```

**GTK4 (Fedora):**

```
sudo dnf install gtk4-devel pkgconfig
```

**GTK4 (Arch Linux):**

```
sudo pacman -S gtk4 pkg-config
```

## Installation

### Building from Source

#### Standard Build (Command-Line Interface)

To compile MIRAK without graphical interface support (statically linked with musl):

```
cargo build --release --target x86_64-unknown-linux-musl
```

#### GUI-Enabled Build

**Important**: GUI builds CANNOT use musl due to GTK4 dynamic linking requirements. The build must target the native system architecture.

**Build with GUI Features Enabled (native target):**

```
cargo build --release --features gui
```

**Note**: GUI builds require GTK4 runtime libraries to be present on the target system. The resulting binary will be dynamically linked against system libraries, unlike the musl-based static build.

### Pre-built Binaries

Pre-compiled binaries are available through the project's GitHub Releases page:

- **CLI version**: Statically linked with musl for maximum compatibility
- **GUI version**: Dynamically linked against GTK4 (requires GTK4 runtime)

## Usage

### Testing Environment Setup

MIRAK provides comprehensive testing through a virtualized environment using Vagrant. This approach enables reproducible security auditing across multiple Linux distributions.

#### Virtual Machine Management

**Navigate to the Vagrant directory:**

```
cd vagrant-VM's/
```

The benchmark runner script is stored in `vagrant-VM's/benchmark_script.sh` and mounted directly into each VM through `/vagrant`. Vagrant provisioning also creates a symbolic link for the `mirak-app` directory at `/home/vagrant/mirak-app`, so no application files or API key are copied into the guest filesystem.

**Initialize and provision the virtual machines:**

```
vagrant up
```

**Establish SSH connection to a specific VM:**

**Ubuntu:**

```
vagrant ssh ubuntu
```

**Debian:**

```
vagrant ssh debian
```

**Fedora:**

```
vagrant ssh fedora
```

#### Running the Scanner

The MIRAK binary resides in the vagrant user's HOME directory (`/home/vagrant/mirak-app/`) and supports the following execution modes:

**Display Help Menu:**

```
./mirak-app/mirak -h
```

**Execute Scanner with API Key (CLI mode):**

```
./mirak-app/mirak -f mirak-app/api_key.txt
```

**Execute Scanner with GUI Interface:**

```
./mirak-app/mirak -g
```

**Note**: When using the GUI mode with `-g` flag, the API key will be entered through the graphical interface after the application launches. The scanner will prompt for the API key within the GUI window.

**Command Line Options:**

- `-f`: Specify API key file path (CLI mode)
- `-g`: Launch graphical user interface (API key will be requested in GUI)

#### Running Benchmark Tests

The benchmark script provides comprehensive performance evaluation of MIRAK against industry-standard vulnerability scanners. It measures and compares resource usage (CPU, memory) and execution time across multiple scanning tools.

**Execute the benchmark script:**

```
./benchmark_script.sh
```

**Included Benchmark Comparisons:**
- **MIRAK**: Custom RPKI vulnerability scanner
- **Trivy**: Container and filesystem scanner
- **Grype**: SBOM-based vulnerability detection
- **Vuls**: Operating system vulnerability scanner

**Benchmark Output:**
The script generates timestamped result directories in `benchmarks/YYYYMMDD_HHMMSS_hostname/` containing:
- `*_report.txt`: Raw vulnerability scanner output
- `*_timeseries.csv`: Performance metrics (timestamp, elapsed time, CPU usage, memory consumption)

Each benchmark run creates a unique timestamped folder to preserve multiple test results, enabling comparative analysis and performance tracking over time.

### Architecture

MIRAK is engineered with the following technical characteristics:

**Core Components:**
- **Language**: Rust (memory-safe systems programming)
- **Target Platforms**:
  - CLI: x86_64 Linux (musl-based static binaries)
  - GUI: x86_64 Linux (dynamically linked against GTK4)
- **Key Dependencies**:
  - **Routinator**: RPKI validator for BGP security testing
  - **Security Tools**: Trivy, Grype, Vuls (additional vulnerability scanners)
  - **GTK4**: GUI framework (required for GUI builds)

**Build Characteristics:**
- **Memory Safety**: Rust's ownership model eliminates buffer overflow vulnerabilities
- **CLI Build**: Static linking with musl for cross-distribution compatibility
- **GUI Build**: Dynamic linking against system GTK4 libraries

### Vagrant Provisioning

The Vagrant provisioning process automatically configures:

**Security Tool Installation:**
- **Trivy**: Container and filesystem vulnerability scanner
- **Grype**: SBOM-based vulnerability detection
- **Vuls**: Vulnerability scanner for operating systems

**Development Environment:**
- Build-essential packages (GCC, Make, Git)
- Required system libraries and headers
- Network configuration for public network access

This comprehensive setup enables seamless integration into CI/CD pipelines, allowing organizations to automate security validation of their BGP infrastructure.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
