
# CAS Rust Core Library (`cas-lib`)

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/7bXXCQj45q)

## Overview

CAS Rust Core Library (`cas-lib`) is a unified cryptographic abstraction layer for Rust, designed to provide secure, high-performance access to industry-standard cryptographic algorithms. Acting as a wrapper over trusted libraries such as RustCrypto and Dalek-Cryptography, `cas-lib` enables seamless integration with higher-level languages and FFI layers, including C, TypeScript, Python, and .NET.

- **Official Crate:** [cas-lib on crates.io](https://crates.io/crates/cas-lib)

## Features

- Modern cryptographic primitives: digital signatures (RSA, Ed25519), hashing, key exchange, symmetric and asymmetric encryption, password hashing, and more
- Centralized entry point for FFI bindings: C, TypeScript, Python, .NET
- Built on top of well-established, open-source cryptography libraries
- Thread-safe, high-performance Rust implementation
- Cross-platform support: Windows, Linux

## Documentation & References

`cas-lib` builds on the work of leading cryptography projects. For detailed algorithm documentation and implementation notes, please refer to:
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## Usage Examples

See practical usage and code samples in our [Examples](./docs/EXAMPLES.md).

## Supported Platforms

- [X] Windows x64
- [X] Linux x64

## Disclaimer

This library leverages several cryptographic crates via our core FFI [layer](./src). Many of these crates have not undergone formal security audits. Use this library at your own risk and always review the underlying cryptographic implementations for your security requirements.

---

For questions, support, or to contribute, join our Discord or visit the [GitHub repository](https://github.com/Cryptographic-API-Services/cas-lib).
