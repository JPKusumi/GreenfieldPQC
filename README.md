# GreenfieldPQC: Post-Quantum Cryptography Library

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet Version](https://img.shields.io/nuget/v/GreenfieldPQC.svg)](https://www.nuget.org/packages/GreenfieldPQC/)

GreenfieldPQC is a slim, post-quantum-ready cryptography library focused on essential primitives for symmetric encryption, hashing, and PQC signatures/KEMs. It includes Kusumi512 (novel ARX stream cipher), Kusumi512Poly1305 (AEAD), SHA256/SHA512 (Microsoft wrappers), Kyber (KEM), and Dilithium (signatures) via P/Invoke to oqs.dll. Designed for efficiency in .NET, with constant-time ops and low memory.

**Key Features:**
- **PQC Primitives**: Kyber/Dilithium for quantum-safe KEM/signing.  
- **Symmetric**: Kusumi512 for high-speed 512-bit encryption.  
- **Hashing**: Simple wrappers for SHA256/512.  
- **API Simplicity**: Factory pattern for instantiation; synchronous and asynchronous methods.  
- **Benchmarked**: Kusumi512 beats Threefish-512 in speed/memory.  
- **Dependencies**: Bundles oqs.dll for multi-platform (win/linux/osx, x64/arm64).  

This library is suitable for greenfield projects transitioning to the "new normal" of quantum-safe cryptography. **Warning**: Not formally audited; use in production at your own risk. Always combine with authenticators for AEAD.

## Installation

Via NuGet:
```
dotnet add package GreenfieldPQC
```

Requires .NET 8.0+. Enable `<AllowUnsafeBlocks>true</AllowUnsafeBlocks>` in your .csproj for optimizations. oqs.dll bundled for supported platforms.

## Quick Start
```csharp
using GreenfieldPQC.Cryptography;
using GreenfieldPQC.Cryptography.Parameters;
using System.Text;

var key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
var nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
ISymmetricCipher cipher = CryptoFactory.CreateKusumi512(key, nonce); // Use interface for mocking

string plaintext = "Hello, PQC!";
byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
byte[] ciphertext = cipher.EncryptSync(plaintextBytes);
byte[] decrypted = cipher.DecryptSync(ciphertext);

Console.WriteLine(Encoding.UTF8.GetString(decrypted)); // "Hello, PQC!"
```

## API Documentation

Namespace: `GreenfieldPQC.Cryptography`

### CryptoFactory
Static factory for keys, nonces, and instances.

- **GenerateKey(CipherAlgorithm alg)**: Random key.
  - `Kusumi512`/`Kusumi512Poly1305`: 64 bytes.
  - `Kyber`/`Dilithium`: Algorithm-specific.
  - Example: `byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);`

- **GenerateNonce(CipherAlgorithm alg)**: Random nonce (12 bytes for Kusumi).
  - Example: `byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);`

- **CreateKusumi512(byte[] key, byte[] nonce)**: Kusumi512 instance.
- **CreateKusumi512Poly1305(byte[] key, byte[] nonce)**: AEAD instance.

- **ComputeSHA256(byte[] data)**: SHA-256 hash.
- **ComputeSHA512(byte[] data)**: SHA-512 hash.
  - Example: `byte[] hash = CryptoFactory.ComputeSHA512(data);`

Supported Algorithms (Enum: `CipherAlgorithm`): Kusumi512, Kusumi512Poly1305, Kyber, Dilithium, SHA256, SHA512.

### ISymmetricCipher (for Kusumi512/Kusumi512Poly1305)
Interface for symmetric ops (useful for mocking/testing).

- **AlgorithmName**: String property (e.g., "Kusumi512").
- **EncryptSync(byte[] plaintext)**: Returns ciphertext (with tag for AEAD).
- **DecryptSync(byte[] ciphertext)**: Returns plaintext (verifies tag for AEAD).
- **Encrypt/Decrypt (async)**: Task-wrapped.
- **EncryptInPlaceSync(Span<byte> io)**: In-place (not for AEAD).
- **DecryptInPlaceSync(Span<byte> io)**: Symmetric to above.
- **EncryptInPlace/DecryptInPlace (async)**: Memory<byte> versions.
- **EncryptStreamSync(Stream in, Stream out, int buf=4096, Func<long, byte[]>? nonceGen=null)**: Stream encryption.
- **DecryptStreamSync**: Stream decryption.
- **EncryptStream/DecryptStream (async)**: With progress, cancellation, async nonceGen.

For AEAD: Ciphertext appends 128-bit tag; decryption throws on invalid.

### Asymmetric cryptography (Kyber and Dilithium)
Kyber/Dilithium via P/Invoke to oqs.dll.

#### Kyber (KEM)
- Constructor: `new Kyber(new KyberParameters(level))` (512/768/1024).
- **GenerateKeyPairSync()**: (publicKey, privateKey).
- **EncapsulateSync(byte[] publicKey)**: (sharedSecret, ciphertext).
- **DecapsulateSync(byte[] ciphertext, byte[] privateKey)**: sharedSecret.

#### Dilithium (Signatures)
- Constructor: `new Dilithium(new DilithiumParameters(level))` (2/3/5).
- **GenerateKeyPairSync()**: (publicKey, privateKey).
- **SignSync(byte[] message, byte[] privateKey)**: signature.
- **VerifySync(byte[] message, byte[] signature, byte[] publicKey)**: bool.
- **GetSignatureLength()**: Expected sig size.

Parameters in `GreenfieldPQC.Cryptography.Parameters`.


## Usage Examples

### Hashing
```csharp
byte[] data = Encoding.UTF8.GetBytes("Hash me");  

// Static (one-off, thread-safe)  
byte[] hash = CryptoFactory.ComputeSHA256(data); // or ComputeSHA256(stream)  
byte[] sha512 = CryptoFactory.ComputeSHA512(data);  

// Instance (reusable per-thread)  
using SHA256 sha = SHA256.Create();  
byte[] hash = sha.ComputeHash(data); // or sha.ComputeHash(stream)  
```

### AEAD Encryption
```csharp
ISymmetricCipher cipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
byte[] ciphertextWithTag = cipher.EncryptSync(plaintextBytes);
byte[] decrypted = cipher.DecryptSync(ciphertextWithTag);
```

### Stream Encryption
```csharp
using var input = File.OpenRead("file.dat");
using var output = File.Create("enc.dat");
ISymmetricCipher cipher = CryptoFactory.CreateKusumi512(key, nonce);
var progress = new Progress<double>(p => Console.WriteLine($"{p:P}"));
Func<long, Task<byte[]>> nonceGen = async bytes => CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
await cipher.EncryptStream(input, output, progress: progress, nonceGenerator: nonceGen);
```

### Kyber KEM
```csharp
var kyber = new Kyber(new KyberParameters(1024));
var (pk, sk) = kyber.GenerateKeyPairSync();
var (ssSender, ct) = kyber.EncapsulateSync(pk);
byte[] ssReceiver = kyber.DecapsulateSync(ct, sk);
// Verify: CryptographicOperations.FixedTimeEquals(ssSender, ssReceiver)
```

### Dilithium Signing
```csharp
var dilithium = new Dilithium(new DilithiumParameters(5));
var (pubKey, privKey) = dilithium.GenerateKeyPairSync();
byte[] sig = dilithium.SignSync(plaintextBytes, privKey);
bool verified = dilithium.VerifySync(plaintextBytes, sig, pubKey);
```

## Security Considerations
- Nonce uniqueness critical.
- Quantum-safe with large keys/PQC.
- Constant-time; audit for production.
