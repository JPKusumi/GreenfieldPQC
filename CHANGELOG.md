# Changelog

All notable changes to GreenfieldPQC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.4] - 2026-03-31

### Added

#### New API Members
- **`IJweProvider.CreateJwe(ReadOnlySpan<byte> payloadBytes, byte[] publicKey)`**: New overload that accepts the payload as raw bytes instead of an `object`. This avoids the intermediate JSON serialization string and keeps callers in `byte[]` land, so they can control the lifetime of the plaintext buffer. **Prefer this for sensitive byte[] payloads.**
- **`IJweProvider.DecryptJweBytes(string jweToken, byte[] privateKey)`**: New method that returns the decrypted JWE payload as `byte[]` instead of a `string`. Because .NET strings are immutable and cannot be reliably zeroed, callers that need best-effort plaintext memory hygiene should use this method and call `CryptographicOperations.ZeroMemory` on the returned array when finished. **Prefer this when the ability to clear plaintext from memory is required.**

#### Implementation / Internal Changes
- Updated XML doc comments on `IJweProvider` to include explicit security guidance: never log decrypted payloads or key material; prefer the new `byte[]` overloads for sensitive data.
- Existing `CreateJwe(object, byte[])` and `DecryptJwe(string, byte[])` APIs are unchanged and fully backwards compatible.
- **`Kusumi512.Dispose()`**: Now overrides the base `Dispose()` to explicitly clear `_startState`, `_workingState`, and `_keystreamBuffer` — the arrays that hold key-derived state — before clearing the raw key and nonce bytes. This is best-effort managed-memory hygiene; the GC and JIT may still retain copies.
- **`Kusumi512Poly1305.Dispose()`**: Now overrides `Dispose()` to dispose the inner `Kusumi512` instance (triggering the state clearing above) before the base class clears the raw key and nonce.
- **Stream buffer clearing**: `Kusumi512.EncryptStream`, `Kusumi512.EncryptStreamAsync`, and all four `Kusumi512Poly1305` stream methods now clear their local `buffer` (and `segmentBuffer` for AEAD) in `finally` blocks after the stream operation completes or fails.
- **AEAD ephemeral key material clearing**: `Kusumi512Poly1305.Encrypt`, `Decrypt`, `EncryptAsync`, and `DecryptAsync` now clear `poly1305Key` (and the tag comparison arrays in the decrypt path) in `finally` blocks.

### Security Guidance
- Do not log or include plaintext payloads or encryption keys in telemetry. Strings in .NET are immutable and cannot be reliably zeroed; use the new `byte[]`-returning `DecryptJweBytes` and the `ReadOnlySpan<byte>`-accepting `CreateJwe` overload for sensitive payloads, and zero the arrays with `CryptographicOperations.ZeroMemory` when done.
- Note: best-effort zeroing applies only to managed memory. Native library (liboqs) behavior for key material passed via P/Invoke is outside GreenfieldPQC's control.

## [1.1.3] - 2026-03-16

### Fixed
- Improved resolution of the native liboqs library when loading on Linux.

#### New API Members
None. No public API surface changes in this release.

## [1.1.2] - 2026-02-06

### Fixed
- Minor fixes and stability improvements.

#### New API Members
None. No public API surface changes in this release.

## [1.1.0] - 2026-02-05

### Added

#### New API Members
- **`CryptoFactory.CreateJwsProvider(int dilithiumLevel = 3)`**: New factory method. Returns an `IJwsProvider` for producing and verifying post-quantum signed JWTs using Dilithium. Dilithium levels: 2, 3, 5.
- **`CryptoFactory.CreateJwsProvider(DilithiumSecurityLevel level)`**: Enum overload of the above; prefer this for new code.
- **`CryptoFactory.CreateJweProvider(int kyberLevel = 3, CipherAlgorithm kusumiAlgorithm = CipherAlgorithm.Kusumi512)`**: New factory method. Returns an `IJweProvider` for producing and verifying post-quantum encrypted JWTs using Kyber + Kusumi512. Kyber levels: 1, 3, 5.
- **`CryptoFactory.CreateJweProvider(KyberSecurityLevel level, CipherAlgorithm kusumiAlgorithm)`**: Enum overload of the above; prefer this for new code.
- **`IJwsProvider`** (new interface):
  - `CreateJws(object payload, byte[] privateKey)`: Signs the payload and returns a compact three-segment JWS token (`header.payload.signature`).
  - `VerifyJws(string jwsToken, byte[] publicKey)`: Verifies the signature and returns the deserialized payload; throws on invalid token.
- **`IJweProvider`** (new interface):
  - `CreateJwe(object payload, byte[] publicKey)`: Encrypts the payload and returns a compact five-segment JWE token (`header.encrypted_key.iv.ciphertext.tag`).
  - `DecryptJwe(string jweToken, byte[] privateKey)`: Decrypts the token and returns the raw JSON payload string; throws on invalid token.

## [1.0.1] - 2025-07-20

### Added

#### New API Members
- **`IKeyEncapsulationMechanism`** (new interface): Abstraction for Kyber operations — `GenerateKeyPair()`, `Encapsulate(byte[] publicKey)`, `Decapsulate(byte[] ciphertext, byte[] privateKey)` — enabling mocking and dependency injection.
- **`ISigner`** (new interface): Abstraction for Dilithium operations — `GenerateKeyPair()`, `Sign(byte[] message, byte[] privateKey)`, `Verify(byte[] message, byte[] signature, byte[] publicKey)`, `GetSignatureLength()` — enabling mocking and dependency injection.
- **`CryptoFactory.CreateKyber(KyberSecurityLevel level)`**: Enum-based factory overload returning `IKeyEncapsulationMechanism`; prefer this over the `int`-parameter overload for new code.
- **`CryptoFactory.CreateDilithium(DilithiumSecurityLevel level)`**: Enum-based factory overload returning `ISigner`; prefer this over the `int`-parameter overload for new code.

#### Documentation / Other Changes
- Enhanced README with structured component details, key size tables for Kyber/Dilithium, expanded API examples (including async/stream), and security considerations.
- NuGet package tags/keywords in .csproj for better discoverability (e.g., post-quantum-cryptography, pqc, kyber, dilithium).

### Fixed
- Minor API clarifications and examples to align with best practices.

No breaking changes; fully backward-compatible with 1.0.0.

## [1.0.0] - 2025-07-15

### Added

#### New API Members
- **`CryptoFactory`**: Static factory class. Key methods: `CreateKusumi512(byte[] key, byte[] nonce)`, `CreateKyber(int parameter)`, `CreateDilithium(int level)`, `CreateSHA256()`, `CreateSHA512()`, `GenerateKey(CipherAlgorithm)`, `GenerateNonce(CipherAlgorithm)`.
- **`ISymmetricCipher`**: Interface for Kusumi512/Kusumi512Poly1305 — `Encrypt`, `Decrypt`, `EncryptInPlace`, `DecryptInPlace`, `EncryptAsync`, `DecryptAsync`, `EncryptInPlaceAsync`, `DecryptInPlaceAsync`, `EncryptStream`, `DecryptStream`, `EncryptStreamAsync`, `DecryptStreamAsync`.
- **`IHashAlgorithm`**: Interface for SHA256/SHA512 — `ComputeHash(byte[])`, `ComputeHash(Stream)`.
- **`Kusumi512`**: Post-quantum stream cipher implementation (512-bit key, 12-byte nonce).
- **`Kusumi512Poly1305`**: AEAD scheme combining Kusumi512 + Poly1305 (512-bit key, 16-byte appended MAC tag).
- Benchmarks and basic unit tests.

[1.1.4]: https://github.com/JPKusumi/GreenfieldPQC/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/JPKusumi/GreenfieldPQC/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/JPKusumi/GreenfieldPQC/compare/v1.1.0...v1.1.2
[1.1.0]: https://github.com/JPKusumi/GreenfieldPQC/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/JPKusumi/GreenfieldPQC/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/JPKusumi/GreenfieldPQC/releases/tag/v1.0.0