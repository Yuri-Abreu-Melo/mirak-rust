# Mirak: BGP RPKI Validator Vulnerability Scanner

## Abstract

Mirak is a vulnerability scanner engineered in Rust, specifically designed to audit BGP RPKI validator implementations such as Routinator. The tool enables rapid identification of security vulnerabilities in critical internet routing infrastructure, providing security researchers and network administrators with automated validation capabilities.

## Introduction

Border Gateway Protocol (BGP) security relies heavily on Resource Public Key Infrastructure (RPKI) validators to prevent route hijacking and prefix misappropriation. The Routinator RPKI validator, a critical component in this ecosystem, has been subject to various security vulnerabilities. Mirak addresses the critical need for automated security auditing of these BGP infrastructure components, providing a reliable tool to validate RPKI validator deployments.

## System Architecture and Testing Environment

### Virtual Machine Infrastructure

The testing environment provisions three distinct Linux distributions:

- **Ubuntu 22.04 LTS** (Jammy)
- **Debian 12** (Bookworm)
- **Fedora 43**

Each virtual machine is configured with 2GB of RAM and 2 CPU cores, providing adequate resources for comprehensive vulnerability scanning tests.

### Deployment Procedure

#### Binary Distribution

The compiled Mirak binary must be placed within the `mirak-app` directory located inside `vagrant-VM's/`. This directory already contains the required API key file (`api_key.txt`) necessary for scanner authentication and operation.

#### Building the Mirak Binary

##### Prerequisites for Standard Build

**Required System Dependencies:**

- **musl**: Lightweight C standard library implementation for static linking
  - Ubuntu/Debian: `sudo apt install musl-tools`
  - Fedora: `sudo dnf install musl-gcc`

**Rust Build Environment Setup:**
`rustup target add x86_64-unknown-linux-musl`

##### Standard Build (Command-Line Interface)

To compile Mirak without graphical interface support (statically linked with musl):
`cargo build --release --target x86_64-unknown-linux-musl`

##### GUI-Enabled Build

**Important**: GUI builds CANNOT use musl due to GTK4 dynamic linking requirements. The build must target the native system architecture.

**Install GTK4 Development Libraries:**
`# Ubuntu/Debian`
`sudo apt install libgtk-4-dev pkg-config`

`# Fedora`
`sudo dnf install gtk4-devel pkgconfig`

**Build with GUI Features Enabled (native target):**
`cargo build --release --features gui`

**Note**: GUI builds require GTK4 runtime libraries to be present on the target system. The resulting binary will be dynamically linked against system libraries, unlike the musl-based static build.

### Alternative: Pre-built Binaries

Pre-compiled binaries are available through the project's GitHub Releases page:

- **CLI version**: Statically linked with musl for maximum compatibility
- **GUI version**: Dynamically linked against GTK4 (requires GTK4 runtime)

## Testing Methodology

### Virtual Machine Management

1. Navigate to the Vagrant directory:
   `cd vagrant-VM's/`

2. Initialize and provision the virtual machines:
   `vagrant up`

3. Establish SSH connection to a specific VM:
   `vagrant ssh ubuntu    # or debian, fedora`

### Execution Procedures

#### Scanner Command Structure

The Mirak binary resides in the vagrant user's HOME directory (`/home/vagrant/mirak-app/`) and supports the following execution modes:

**Display Help Menu:**
`./mirak-app/mirak -h`

**Execute Scanner with API Key (CLI mode):**
`./mirak-app/mirak -f mirak-app/api_key.txt`

**Execute Scanner with GUI Interface:**
`./mirak-app/mirak -g`

**Note**: When using the GUI mode with `-g` flag, the API key will be entered through the graphical interface after the application launches. The scanner will prompt for the API key within the GUI window.

**Command Line Options:**

- `-f`: Specify API key file path (CLI mode)
- `-g`: Launch graphical user interface (API key will be requested in GUI)

### Vulnerability Detection Configuration

The scanner specifically targets CVE-2024-1622, affecting Routinator RPKI validator versions up to 0.12.2. The Routinator version is configurable within the Vagrantfile:

`# In Vagrantfile, modify the following line to test different versions`
`cargo install routinator@0.12.2  # Change version to test`

## Technical Architecture

### Core Components

- **Language**: Rust (memory-safe systems programming)
- **Target Platforms**:
  - CLI: x86_64 Linux (musl-based static binaries)
  - GUI: x86_64 Linux (dynamically linked against GTK4)
- **Key Dependencies**:
  - **Routinator**: RPKI validator for BGP security testing
  - **Security Tools**: Trivy, Grype, Vuls (additional vulnerability scanners)
  - **GTK4**: GUI framework (required for GUI builds)

### Build Characteristics

- **Memory Safety**: Rust's ownership model eliminates buffer overflow vulnerabilities
- **CLI Build**: Static linking with musl for cross-distribution compatibility
- **GUI Build**: Dynamic linking against system GTK4 libraries

## Continuous Integration and Deployment Integration

The Vagrant provisioning process automatically configures:

### Security Tool Installation

- **Trivy**: Container and filesystem vulnerability scanner
- **Grype**: SBOM-based vulnerability detection
- **Vuls**: Vulnerability scanner for operating systems

### Development Environment

- Build-essential packages (GCC, Make, Git)
- Required system libraries and headers
- Network configuration for public network access

This comprehensive setup enables seamless integration into CI/CD pipelines, allowing organizations to automate security validation of their BGP infrastructure.

## Security Considerations

- **CVE-2024-1622**: Routinator RPKI validator vulnerability
- **Impact**: Affects BGP route validation integrity
- **Mitigation**: Mirak enables rapid identification of vulnerable deployments

## Conclusion

Mirak provides network security professionals with a robust solution for auditing BGP RPKI validator implementations. By combining Rust's safety guarantees with comprehensive vulnerability detection capabilities, Mirak addresses the critical need for automated security validation in modern internet routing infrastructure.
