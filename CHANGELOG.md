# Changelog

All notable changes to GreenfieldPQC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4] - 2026-03-31

### Added
- **`IJweProvider.DecryptJweBytes`**: New method that returns the decrypted JWE payload as `byte[]` instead of a `string`. Because .NET strings are immutable and cannot be reliably zeroed, callers that need best-effort plaintext memory hygiene should use this overload and call `Array.Clear` on the returned array when finished.
- **`IJweProvider.CreateJwe(ReadOnlySpan<byte>, byte[])`**: New overload that accepts the payload as raw bytes instead of an `object`. This avoids the intermediate JSON serialization string and keeps callers in `byte[]` land, so they can control the lifetime of the plaintext buffer.
- Existing `CreateJwe(object, byte[])` and `DecryptJwe(string, byte[])` APIs are unchanged and fully backwards compatible.
- Updated XML doc comments on `IJweProvider` to include explicit security guidance: never log decrypted payloads or key material; prefer the new `byte[]` overloads for sensitive data.

### Security guidance
- Do not log or include plaintext payloads or encryption keys in telemetry. Strings in .NET are immutable and cannot be reliably zeroed; use the new `byte[]`-returning `DecryptJweBytes` and the `ReadOnlySpan<byte>`-accepting `CreateJwe` overload for sensitive payloads, and zero the arrays with `Array.Clear` when done.
- Note: best-effort zeroing applies only to managed memory. Native library (liboqs) behavior for key material passed via P/Invoke is outside GreenfieldPQC's control.

As of March 31, 2026, v1.1.4 was released with best-effort secret/plaintext handling improvements focused on JWT providers.

As of March 16, 2026, v1.1.3 was released with minor fixes: Improved resolution of the library when loading on Linux.

As of February 6, 2026, v1.1.2 was released with minor fixes.

As of February 5, 2026, v1.1.0 was released with new features: quantum safe JWS and JWE creation and verification for JWTs

As of August 30, 2025, a test vector in the TECHNICAL_SPEC.md was updated.

As of August 6, 2025, the README improved again.

As of July 31, 2025, the README has been substantially reworked and updated.

An earlier version of the README was recommending &lt;AllowUnsafeBlocks&gt;true&lt;/AllowUnsafeBlocks&gt; in the project file. It's not necessary for users who are consuming the NuGet package, so this advice was removed. The Installation section is now simplified.

An earlier version of the README was incorrect about the nonce size.
For Kusumi512 and Kusumi512Poly1305, the nonce is 12 bytes (96 bits), not 16 bytes.
The README has been corrected accordingly.

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