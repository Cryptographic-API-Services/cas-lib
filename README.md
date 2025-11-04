# cas-lib

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/UAGqKfmvUS)

## Crates.io / User Announcements
You can find the official crate [here](https://crates.io/crates/cas-lib). As of this writing we have about 17K downloads, we encourage feedback/questions in the [Github issues](https://github.com/Cryptographic-API-Services/cas-lib/issues), we haven't gotten much feedback on the library considering the download size. 

## Overview
This is our experimental core library which takes advantage of Rust's thread safe nature to provide an abstraction layer to higher level languages to run industry standard crytographic operations.
This crate is not us writing cryptography operations directly in Rust, rather is it a wrapper layer for the following organizations who have done lots of hard work for us. The main usage of this library is providing a centralized entry point for various langague FFI layers throughout CAS [C FFI](https://github.com/Cryptographic-API-Services/cas-core-lib), [Typescript](https://github.com/Cryptographic-API-Services/cas-typescript-sdk), [Python](https://github.com/Cryptographic-API-Services/cas-python-sdk).

## Consuming Library Documentation
We utilize some smart people's existing work and we believe their documentation should be reviewed when possible.
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## [Examples](https://github.com/Cryptographic-API-Services/cas-lib/blob/main/docs/EXAMPLES.md)

## Disclaimer
Many of the cryptographic crates that are utilized in our core FFI [layer](./src) have never had a security audit performed. Utilize this SDK at your own risk.
