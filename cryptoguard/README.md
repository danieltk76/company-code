# CryptoGuard

CryptoGuard is a high-performance, enterprise-grade cryptographic file processor built in Rust. It provides comprehensive encryption, decryption, digital signing, and integrity verification capabilities for securing sensitive files and data.

## Features

### Core Cryptographic Operations
- **File Encryption/Decryption**: AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305
- **Hash Generation**: BLAKE3, SHA-256, SHA-3, SHA-512
- **Digital Signatures**: RSA, Ed25519, X25519 key generation and signing
- **Key Derivation**: Argon2, PBKDF2, scrypt password-based key derivation
- **Secure Deletion**: Multi-pass overwriting with verification

### Advanced Features
- **Batch Processing**: Recursive directory operations
- **Compression**: Optional file compression before encryption
- **Integrity Verification**: Automated file integrity checking
- **Network Daemon**: Remote cryptographic operations via HTTPS API
- **Benchmarking**: Performance testing of cryptographic algorithms
- **Memory Safety**: Zero-copy operations with memory-safe Rust implementation

### Enterprise Integration
- **Configuration Management**: YAML/JSON configuration files
- **Logging**: Structured logging with multiple output formats  
- **Cross-Platform**: Windows, macOS, Linux support
- **Hardware Acceleration**: Optional CPU-specific optimizations
- **API Server**: RESTful API for remote operations

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/cryptoguard/cryptoguard/releases):

```bash
# Linux x86_64
wget https://github.com/cryptoguard/cryptoguard/releases/latest/download/cryptoguard-linux-x64.tar.gz
tar -xzf cryptoguard-linux-x64.tar.gz
sudo cp cryptoguard /usr/local/bin/

# macOS Universal
curl -L https://github.com/cryptoguard/cryptoguard/releases/latest/download/cryptoguard-macos.zip -o cryptoguard-macos.zip
unzip cryptoguard-macos.zip
sudo cp cryptoguard /usr/local/bin/

# Windows x64
# Download and extract cryptoguard-windows-x64.zip from releases
```

### Build from Source

#### Prerequisites
- Rust 1.70.0 or later
- C compiler (gcc/clang/MSVC)
- OpenSSL development headers (Linux/macOS)

#### Build Steps

```bash
# Clone repository
git clone https://github.com/cryptoguard/cryptoguard.git
cd cryptoguard

# Build release version
cargo build --release

# Install to system
cargo install --path .

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

#### Cross-compilation

```bash
# Install cross-compilation targets
rustup target add x86_64-pc-windows-gnu
rustup target add aarch64-apple-darwin

# Build for different targets
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target aarch64-apple-darwin
```

## Quick Start

### Basic File Operations

```bash
# Encrypt a file
cryptoguard encrypt -i document.pdf -o document.pdf.cge

# Encrypt with specific algorithm
cryptoguard encrypt -i data.txt -a chacha20-poly1305 -o data.txt.encrypted

# Decrypt a file
cryptoguard decrypt -i document.pdf.cge -o document_decrypted.pdf

# Encrypt directory recursively
cryptoguard encrypt -i /path/to/directory --recursive -o /path/to/encrypted_dir
```

### Key Management

```bash
# Generate Ed25519 key pair
cryptoguard keygen -a ed25519 -o mykey

# Generate RSA key pair with password protection
cryptoguard keygen -a rsa --key-size 4096 -o rsa_key --password

# Generate X25519 keys for key exchange
cryptoguard keygen -a x25519 -o exchange_key
```

### Digital Signatures

```bash
# Sign a file
cryptoguard sign -i document.pdf -k private_key.priv -o document.pdf.signed

# Create detached signature
cryptoguard sign -i document.pdf -k private_key.priv --detached -o document.pdf.sig

# Verify signature
cryptoguard verify -i document.pdf -s document.pdf.sig -p public_key.pub
```

### Hash Operations

```bash
# Generate BLAKE3 hash
cryptoguard hash -i largefile.bin -a blake3

# Hash directory recursively with JSON output
cryptoguard hash -i /path/to/directory --recursive --format-json -o hashes.json

# Multiple hash algorithms
cryptoguard hash -i file.txt -a sha256
cryptoguard hash -i file.txt -a sha3-256
```

## Configuration

### Configuration File

Create `~/.config/cryptoguard/config.yaml`:

```yaml
# Default encryption algorithm
default_algorithm: "aes-256-gcm"

# Buffer size for file operations (bytes)
buffer_size: 65536

# Maximum file size for operations (bytes)
max_file_size: 10737418240  # 10GB

# Enable unsafe operations (use with caution)
allow_unsafe_operations: false

# Log sensitive data (for debugging only)
log_sensitive_data: false

# Reuse nonces (do not enable in production)
reuse_nonce: false
```

### Environment Variables

```bash
export CRYPTOGUARD_CONFIG="/path/to/config.yaml"
export CRYPTOGUARD_LOG_LEVEL="info"
export CRYPTOGUARD_NO_COLOR="1"
```

## Command Reference

### Global Options

```bash
cryptoguard [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>      Configuration file path
  -l, --log-level <LEVEL>  Log level [default: info]
      --no-color           Disable colored output
  -h, --help               Print help information
  -V, --version            Print version information
```

### Commands

#### encrypt
Encrypt files or directories with various algorithms.

```bash
cryptoguard encrypt [OPTIONS] -i <INPUT>

Options:
  -i, --input <PATH>           Input file or directory
  -o, --output <PATH>          Output path
  -a, --algorithm <ALG>        Encryption algorithm [default: aes-256-gcm]
  -k, --key <KEY>              Encryption key (base64: or hex: prefix)
  -p, --password <PASSWORD>    Password for key derivation
      --recursive              Process directories recursively
      --compress               Compress before encryption
      --hash-algorithm <ALG>   Hash algorithm [default: blake3]
```

#### decrypt
Decrypt previously encrypted files.

```bash
cryptoguard decrypt [OPTIONS] -i <INPUT>

Options:
  -i, --input <PATH>        Encrypted input file
  -o, --output <PATH>       Decrypted output path
  -k, --key <KEY>           Decryption key
  -p, --password <PASSWORD> Password for key derivation
      --verify-integrity    Verify file integrity during decryption
```

#### keygen
Generate cryptographic key pairs.

```bash
cryptoguard keygen [OPTIONS] -o <OUTPUT>

Options:
  -a, --algorithm <ALG>    Key algorithm [default: ed25519]
  -o, --output <PATH>      Output path for keys
      --key-size <SIZE>    Key size in bits [default: 4096]
      --password <PASSWORD> Password to encrypt private key
```

#### benchmark
Performance testing of cryptographic operations.

```bash
cryptoguard benchmark [OPTIONS]

Options:
  -a, --algorithms <ALGS>  Algorithms to test [default: all]
  -d, --data-size <SIZE>   Test data size in bytes [default: 1048576]
  -i, --iterations <NUM>   Number of iterations [default: 10]
```

## Network Daemon

### Starting the Daemon

```bash
# Start with default settings
cryptoguard daemon

# Custom port and bind address
cryptoguard daemon -p 8443 -b 127.0.0.1

# Enable TLS
cryptoguard daemon --tls-cert server.crt --tls-key server.key
```

### API Endpoints

The daemon exposes a RESTful API for remote operations:

```http
POST /api/v1/encrypt
POST /api/v1/decrypt
POST /api/v1/sign
POST /api/v1/verify
POST /api/v1/hash
GET  /api/v1/status
```

### Example API Usage

```bash
# Encrypt file via API
curl -X POST https://localhost:8443/api/v1/encrypt \
  -F "file=@document.pdf" \
  -F "algorithm=aes-256-gcm" \
  -F "password=mypassword"

# Get server status
curl https://localhost:8443/api/v1/status
```

## Security Considerations

### Best Practices

1. **Key Management**
   - Store private keys securely with appropriate file permissions (600)
   - Use strong passwords for key encryption
   - Rotate keys regularly
   - Never share private keys

2. **Password Security**
   - Use strong, unique passwords
   - Consider using password managers
   - Enable password-protected key storage

3. **Algorithm Selection**
   - Use AES-256-GCM for maximum security
   - BLAKE3 for fastest hashing with good security
   - Ed25519 for digital signatures

4. **File Handling**
   - Use secure deletion for sensitive files
   - Verify file integrity after encryption/decryption
   - Be aware of metadata leakage

### Compliance

CryptoGuard implements industry-standard cryptographic algorithms:
- **FIPS 140-2** compliant algorithms available
- **NIST SP 800-38D** (AES-GCM) implementation
- **RFC 7539** (ChaCha20-Poly1305) compatible
- **RFC 8032** (Ed25519) signatures

## Performance

### Benchmarking Results

Typical performance on modern hardware (Intel i7-12700K):

| Algorithm | Throughput | Use Case |
|-----------|------------|----------|
| AES-256-GCM | 3.2 GB/s | General encryption |
| ChaCha20-Poly1305 | 2.8 GB/s | Mobile/embedded |
| BLAKE3 | 8.1 GB/s | Fast hashing |
| SHA-256 | 1.2 GB/s | Standard hashing |

### Optimization Tips

1. **Hardware Acceleration**: Enable CPU-specific optimizations
2. **Buffer Size**: Increase buffer size for large files
3. **Parallel Processing**: Use multiple threads for batch operations
4. **SSD Storage**: Use fast storage for temporary files

## Development

### Project Structure

```
src/
├── main.rs              # CLI application entry point
├── crypto.rs            # Core cryptographic operations
├── file_manager.rs      # File system operations
├── key_management.rs    # Key generation and management
├── integrity.rs         # Digital signatures and verification
├── network.rs           # HTTP/HTTPS daemon server
├── config.rs            # Configuration management
└── utils.rs             # Utility functions
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -am 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Create Pull Request

### Development Setup

```bash
# Install development dependencies
cargo install cargo-audit cargo-outdated cargo-edit

# Run security audit
cargo audit

# Check for outdated dependencies  
cargo outdated

# Run all tests with coverage
cargo test --all-features

# Lint code
cargo clippy -- -D warnings

# Format code
cargo fmt --all
```

### Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test '*'

# Property-based testing
cargo test --features proptest

# Benchmark tests
cargo bench
```

## Troubleshooting

### Common Issues

1. **Build Errors**
   ```
   error: failed to run custom build command for `openssl-sys`
   ```
   **Solution**: Install OpenSSL development headers
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libssl-dev

   # macOS
   brew install openssl

   # Windows
   # Use vcpkg or pre-built binaries
   ```

2. **Permission Denied**
   ```
   Error: Permission denied (os error 13)
   ```
   **Solution**: Ensure proper file permissions or run with appropriate privileges

3. **Key Format Errors**
   ```
   Error: Invalid key format
   ```
   **Solution**: Check key encoding (base64: or hex: prefix) and ensure correct format

4. **Memory Issues**
   ```
   Error: Cannot allocate memory
   ```
   **Solution**: Increase available memory or reduce buffer size in configuration

### Debug Mode

```bash
# Enable debug logging
RUST_LOG=debug cryptoguard encrypt -i file.txt

# Trace all operations
RUST_LOG=trace cryptoguard --log-level trace decrypt -i file.cge
```

### Performance Issues

```bash
# Profile application
cargo install cargo-profiler
cargo profiler --bin cryptoguard

# Memory profiling
valgrind --tool=memcheck ./target/release/cryptoguard
```

## License

CryptoGuard is licensed under the MIT License. See [LICENSE](LICENSE) for details.

```
Copyright (c) 2024 CryptoGuard Development Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

## Support

- **Documentation**: [https://cryptoguard.io/docs](https://cryptoguard.io/docs)
- **API Reference**: [https://docs.rs/cryptoguard](https://docs.rs/cryptoguard)
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/cryptoguard/cryptoguard/issues)
- **Discord**: [Join our community](https://discord.gg/cryptoguard)
- **Email**: [support@cryptoguard.io](mailto:support@cryptoguard.io) 