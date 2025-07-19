# Changelog

All notable changes to GreenfieldPQC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-07-20

### Added
- Enhanced README with structured component details, key size tables for Kyber/Dilithium, expanded API examples (including async/stream), and security considerations.
- Interfaces (`IKeyEncapsulationMechanism` for Kyber, `ISigner` for Dilithium) and CryptoFactory extensions for dependency injection (DI) support, improving testability and loose coupling.
- NuGet package tags/keywords in .csproj for better discoverability (e.g., post-quantum-cryptography, pqc, kyber, dilithium).

### Fixed
- Minor API clarifications and examples to align with best practices.

No breaking changes; fully backward-compatible with 1.0.0.

## [1.0.0] - 2025-07-15

### Added
- Initial release with Kusumi512 symmetric cipher, Kusumi512Poly1305 AEAD, Kyber KEM, Dilithium signatures, and SHA256/SHA512 hashing.
- CryptoFactory for instantiation and utilities.
- Benchmarks and basic unit tests.

[1.0.1]: https://github.com/JPKusumi/GreenfieldPQC/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/JPKusumi/GreenfieldPQC/releases/tag/v1.0.0