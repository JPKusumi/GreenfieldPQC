# GreenfieldPQC
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet Version](https://img.shields.io/nuget/v/GreenfieldPQC.svg)](https://www.nuget.org/packages/GreenfieldPQC/)  
NuGet URL - https://www.nuget.org/packages/GreenfieldPQC  
GitHub URL - https://github.com/JPKusumi/GreenfieldPQC

## Quick Overview: Quantum Resistance Available Now  

The world faces the threat of quantum computers with the ability to break current (or old normal) cryptographic systems. To use Post Quantum Cryptography (PQC) will become the new normal. GreenfieldPQC is a .NET library that provides post-quantum cryptographic primitives to secure applications against these future threats. It offers an opinionated subset drawn from available implementations of key encapsulation mechanisms (KEMs), symmetric encryption, digital signatures, and hashing algorithms designed to be resistant to quantum attacks. The goal is to sidestep threats like Grover's algorithm for symmetric ciphers and Shor's for asymmetric ones.  

The subset covers the bases to enable quantum safety from end-to-end. Combine components, e.g., use Kyber for key exchange, Kusumi512 for bulk encryption, Dilithium for signing, and SHA512 for hashing. Use CryptoFactory.GenerateKey and GenerateNonce for secure random generation. Note that Kusumi512 comes in two varieties (Kusumi512 and Kusumi512Poly1305, a MAC version to enable AEAD operation), and that two versions of hashing are included (SHA256 and SHA512).  

Where the old normal was to use 256-bit keys and hashes, the new normal is to use 512-bit keys and hashes. This library provides a simple way to implement this new normal in .NET applications.  

Hence, a key feature of the new normal is that devs and storage systems must accomodate larger data sizes for keys and hashes. While 256 bits is 32 bytes, 512 bits is 64 bytes.  

Package note. This package is best for green field development — new projects, not legacy systems. Corporate, legacy systems need more than code; database schemas may need to change, and they may choose to re-encrypt vulnerable data. Conversely, if you are on a green field project, then you can drop in this package and go. The name, GreenfieldPQC, indicates that brown field redevelopment on legacy systems is out of scope for this package.  

Upon review, Grok has said, "This library is suitable for greenfield projects transitioning to the 'new normal' of quantum-safe cryptography."  

For more commentary from Grok, see REVIEW.md and BENCHMARKS.md in the repo root. **Warning**: Not formally audited; use in production at your own risk.  


**More Features:**
- **API Simplicity**: Factory pattern for instantiation; synchronous and asynchronous methods.  
- **Benchmarked**: Kusumi512 beats Threefish-512 in speed/memory.  
- **Transitive Dependency**: Bundles oqs.dll for multi-platform (win/linux/osx, x64/arm64). Note that win-arm64 is not a supported platform.  
- **NuGet Package**: Easy integration with .NET 8+; no additional configuration needed.

## Installation  

Via NuGet:
```
dotnet add package GreenfieldPQC
```
Requires .NET 8.0+. Bundles oqs.dll, a native dll, as a transitive dependency for supported platforms (win/linux/osx, x64/arm64). No additional configuration needed. Note that win-arm64 is not a supported platform.  

## Quick Start
```csharp
using GreenfieldPQC.Cryptography;
using System.Text;

var key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
var nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
ISymmetricCipher cipher = CryptoFactory.CreateKusumi512(key, nonce); // Use interface for mocking

string plaintext = "Hello, PQC!";
byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
byte[] ciphertext = cipher.Encrypt(plaintextBytes);
byte[] decrypted = cipher.Decrypt(ciphertext);

Console.WriteLine(Encoding.UTF8.GetString(decrypted)); // "Hello, PQC!"
```

## Old Normal vs. New Normal  

GreenfieldPQC enables "future-proof" encryption upgrades with minimal disruption, targeting quantum-resistant primitives for new ("greenfield") projects. Key benefits:  

- **Quantum Resistance**: Kusumi512 offers 512-bit keys for symmetric encryption (effective 256-bit security post-Grover), outperforming Threefish-512 in benchmarks (7-9% faster execution, 40-58% less memory). Kyber and Dilithium are NIST-standardized for asymmetric needs.  
- **Efficiency**: Optimized for .NET (C#), with low overhead—ideal for high-throughput apps like cloud services, IoT, or data pipelines.  
- **Ease of Adoption**: NuGet integration; bundles oqs.dll for native PQC support (via P/Invoke for Kyber and Dilithium); requires .NET 8+.  
- **Risk Mitigation**: Addresses media "drumbeat" on quantum threats; supports compliance (e.g., FIPS-like standards pending NIST finalization).  
- **Benchmarks Summary**: From BENCHMARKS.md (in repo root), Kusumi512 excels in speed and RAM vs. alternatives, making it a practical "new normal" for 512-bit symmetric crypto.  

Evaluate via a proof-of-concept: Install the package and test Kusumi512 for your workload. For ROI, consider avoided breaches in a post-quantum world—contact NIST or consult [xAI's resources](https://x.ai) for broader AI/quantum insights.  

Resources:
- **Cryptography Basics**: [Wikipedia: Cryptography](https://en.wikipedia.org/wiki/Cryptography) – A high-level intro to encryption concepts.  
- **Symmetric vs. Asymmetric Encryption**: [Khan Academy: Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography) – Free videos explaining keys, ciphers, and hashes.  
- **Quantum Threats**: [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) – Explains why quantum computers could break current encryption and the shift to PQC.  
- **Quantum Computing Primer**: [IBM: What is Quantum Computing?](https://www.ibm.com/topics/quantum-computing) – Simple explanation of the "quantum threat" in news stories.  
- **Why Larger Keys Matter**: [Cloudflare: Post-Quantum Cryptography](https://blog.cloudflare.com/post-quantum-cryptography/) – Real-world context on urgency without deep math.  

## End-to-End Example  

Alice and Bob are old friends who love sharing secrets, but in this digital age, they're paranoid about eavesdroppers—like quantum computers that could one day crack traditional key exchanges. Alice wants to send Bob some confidential photos from their latest adventure, but she needs a super-secure way to encrypt them using her new favorite symmetric cipher, Kusumi512, which requires a 512-bit shared key. The problem? They don't have a secure way to agree on that key over the internet without someone intercepting it.

Enter Kyber, the post-quantum hero of key encapsulation mechanisms (KEMs). It's like a magical lockbox that's safe even from future quantum villains. Here's how their story unfolds:

1. **Alice Prepares the Lockbox**: Alice generates a Kyber key pair on her computer—a public key (like an open lock anyone can see) and a private key (the secret code to unlock it). She sends the public key to Bob over the open internet. No worries if someone like Eve intercepts it; the public key is useless without the private one.

2. **Bob Seals the Secret**: Bob receives Alice's public key and decides on a random shared secret (this will become their 512-bit Kusumi512 key). Using Kyber, he "encapsulates" this secret inside a ciphertext—a digital envelope sealed with Alice's public key. Only Alice can open it. Bob sends this ciphertext back to Alice.

3. **Alice Unlocks the Secret**: Alice uses her private key to "decapsulate" the ciphertext, revealing the exact shared secret Bob chose. Now both Alice and Bob have the same 512-bit key, and Eve (even with a quantum computer) can't figure it out because Kyber's lattice-based math is too tricky for Shor's algorithm.

4. **Symmetric Bliss with Kusumi512**: With the shared key in hand, Alice encrypts her photos using Kusumi512 in a mode like CTR (counter mode) for fast streaming. For extra security, she adds authentication with Poly1305, creating an AEAD (Authenticated Encryption with Associated Data) tag to ensure the data isn't tampered with. She sends the encrypted photos and tag to Bob.

5. **Bob Decrypts and Enjoys**: Bob uses the same shared Kusumi512 key to decrypt the photos and verify the Poly1305 tag. If everything checks out, he sees the images perfectly. If not, he knows something's fishy.

In the end, Alice and Bob's communication is quantum-safe from the start (thanks to Kyber) and blazing fast for the bulk data (thanks to Kusumi512's efficiency). This hybrid approach—post-quantum key exchange plus symmetric encryption—is the gold standard for future-proofing, enabled by this GreenfieldPQC toolkit for .NET developers. If quantum threats escalate, they're ready!

### How to Implement the End-to-End Example  

To implement the Alice and Bob scenario in C#, we'll use Kyber for quantum-safe key exchange, SHA512 to derive a 512-bit symmetric key from Kyber's 256-bit shared secret, and Kusumi512Poly1305 for authenticated bulk encryption (AEAD mode). This ensures confidentiality, integrity, and authenticity.  

Assume Alice and Bob have a way to exchange data (e.g., via files or a network channel—out of scope here). We'll use level 1024 for Kyber (high security) and focus on synchronous methods for simplicity. Use using statements for disposal.  

#### Alice's Code (Generate Key Pair, Send Public Key, Receive Ciphertext, Derive Key, Encrypt Data)
```csharp

using GreenfieldPQC.Cryptography;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Step 1: Alice generates Kyber key pair
var kem = CryptoFactory.CreateKyber(1024);
var (alicePublicKey, alicePrivateKey) = kem.GenerateKeyPair();

// Send alicePublicKey to Bob (e.g., save to file)
File.WriteAllBytes("alice_public_key.bin", alicePublicKey);

// Step 3: Alice receives ciphertext from Bob (e.g., read from file)
byte[] bobCiphertext = File.ReadAllBytes("bob_ciphertext.bin");

// Decapsulate to get 256-bit shared secret
byte[] sharedSecret256 = kem.Decapsulate(bobCiphertext, alicePrivateKey);

// Derive 512-bit key via SHA512 hash
byte[] kusumiKey = CryptoFactory.ComputeSHA512(sharedSecret256);  // 64 bytes

// Generate nonce for symmetric encryption
byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);

// Create AEAD cipher
ISymmetricCipher cipher = CryptoFactory.CreateKusumi512Poly1305(kusumiKey, nonce);

// Encrypt data (e.g., a message or file stream)
string plaintext = "Confidential photos data";  // Or read from file/stream
byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
byte[] ciphertextWithTag = cipher.Encrypt(plaintextBytes);

// Send ciphertextWithTag to Bob (e.g., save to file)
File.WriteAllBytes("encrypted_data.bin", ciphertextWithTag);
```  

#### Bob's Code (Receive Public Key, Encapsulate, Send Ciphertext, Derive Key, Decrypt Data)
```csharp

using GreenfieldPQC.Cryptography;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Step 2: Bob receives Alice's public key (e.g., read from file)
byte[] alicePublicKey = File.ReadAllBytes("alice_public_key.bin");

// Create Kyber instance (same level as Alice)
var kem = CryptoFactory.CreateKyber(1024);

// Encapsulate to get 256-bit shared secret and ciphertext
var (sharedSecret256, ciphertext) = kem.Encapsulate(alicePublicKey);

// Send ciphertext to Alice (e.g., save to file)
File.WriteAllBytes("bob_ciphertext.bin", ciphertext);

// Derive 512-bit key via SHA512 hash (same as Alice)
byte[] kusumiKey = CryptoFactory.ComputeSHA512(sharedSecret256);  // 64 bytes

// Generate same nonce (or receive from Alice; here assuming shared or generated identically)
byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);

// Create AEAD cipher
ISymmetricCipher cipher = CryptoFactory.CreateKusumi512Poly1305(kusumiKey, nonce);

// Step 5: Bob receives encrypted data (e.g., read from file)
byte[] ciphertextWithTag = File.ReadAllBytes("encrypted_data.bin");

// Decrypt and verify tag (throws if tampered)
byte[] decryptedBytes = cipher.Decrypt(ciphertextWithTag);
string decrypted = Encoding.UTF8.GetString(decryptedBytes);

Console.WriteLine(decrypted);  // "Confidential photos data"
```
**Notes:**  
• Use secure channels for exchanges if possible, but Kyber ensures the shared secret is safe even over insecure ones.  
• For files/streams: Replace byte arrays with EncryptStreamAsync/DecryptStreamAsync for large data like photos.  
• Verify equality of shared secrets with CryptographicOperations.FixedTimeEquals in tests.  
• Rotate nonces/keys per session; include timestamps in data for replay protection.  
• Error handling: Wrap in try-catch for exceptions like invalid tags.  

### Another Usage Example: Stream Encryption  
```csharp
using var input = File.OpenRead("file.dat");
using var output = File.Create("enc.dat");
ISymmetricCipher cipher = CryptoFactory.CreateKusumi512(key, nonce);
var progress = new Progress<double>(p => Console.WriteLine($"{p:P}"));
Func<long, Task<byte[]>> nonceGen = async bytes => CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
await cipher.EncryptStreamAsync(input, output, progress: progress, nonceGenerator: nonceGen);
```

## Kyber

A post-quantum key encapsulation mechanism (KEM) formerly known as CRYSTALS-Kyber – its formal name has been changed to ML-KEM. ML-KEM is the standardized name adopted by NIST for Kyber. This renaming occurred as part of NIST's finalization of post-quantum cryptography standards in August 2024, where CRYSTALS-Kyber was selected and formalized as ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) under FIPS 203.  

In the developer API, we call it Kyber, but inside the GreenfieldPQC.dll, we use P/Invoke to call into a native dll for the ML-KEM implementation. If you are tracking dependencies, liboqs is a transitive dependency of GreenfieldPQC.  

Kyber yields a 32-byte secret that two parties share without that secret ever crossing the wire. It is a key encapsulation mechanism (KEM) that allows you to securely exchange keys in a post-quantum world.  

Note that 32 bytes is 256 bits. If you hash that with SHA512, then you get a 512-bit digest, usable as a 512-bit encryption key for symmetric cryptography. Both parties can run the hash locally, and they will end up with the same key.  

Key and ciphertext sizes by security level (from FIPS 203):

| Security Level | Public Key (pk) | Private Key (sk) | Ciphertext (ct) |
|----------------|-----------------|------------------|-----------------|
| 512           | 800 bytes      | 1632 bytes      | 768 bytes      |
| 768           | 1184 bytes     | 2400 bytes      | 1088 bytes     |
| 1024          | 1568 bytes     | 3168 bytes      | 1568 bytes     |

**API Highlights** (Security levels: 512, 768, 1024):
- `CryptoFactory.CreateKyber(level)`: Returns IKeyEncapsulationMechanism instance (level: 512, 768, or 1024).
- `IKeyEncapsulationMechanism.GenerateKeyPair()`: Returns (publicKey, privateKey).
- `IKeyEncapsulationMechanism.Encapsulate(byte[] publicKey)`: Returns (sharedSecret, ciphertext).
- `IKeyEncapsulationMechanism.Decapsulate(byte[] ciphertext, byte[] privateKey)`: Returns sharedSecret.

**Example** (using level 1024):
```csharp
using GreenfieldPQC.Cryptography;

var kem = CryptoFactory.CreateKyber(1024);
var (pk, sk) = kem.GenerateKeyPair();
var (ssSender, ct) = kem.Encapsulate(pk);
byte[] ssReceiver = kem.Decapsulate(ct, sk);  // ssSender matches ssReceiver (use CryptographicOperations.FixedTimeEquals to verify)
```

**Best Practices**: Use Kyber to replace quantum-vulnerable classical methods like ECDH for key exchange. Store private keys securely, e.g., in hardware security modules.

## Dilithium

A post-quantum digital signature algorithm originally known as CRYSTALS-Dilithium – its formal name has been changed to ML-DSA. ML-DSA is the standardized name adopted by NIST for Dilithium. This renaming occurred as part of NIST's finalization of post-quantum cryptography standards in August 2024, where CRYSTALS-Dilithium was selected and formalized as ML-DSA (Module-Lattice-Based Digital Signature Algorithm) under FIPS 204.  

In the developer API, we call it Dilithium, but inside the GreenfieldPQC.dll, we use P/Invoke to call into a native dll for the ML-DSA implementation. If you are tracking dependencies, liboqs is a transitive dependency of GreenfieldPQC.  

Dilithium is a digital signature algorithm that allows you to sign messages in a post-quantum world. It is designed to be secure against quantum attacks, making it suitable for long-term data integrity and authenticity.  

Key and signature sizes by security level (from FIPS 204):

| Security Level | Public Key (pk) | Private Key (sk) | Signature (sig) |
|----------------|-----------------|------------------|-----------------|
| 2 (ML-DSA-44) | 1312 bytes     | 2560 bytes      | 2420 bytes     |
| 3 (ML-DSA-65) | 1952 bytes     | 4032 bytes      | 3309 bytes     |
| 5 (ML-DSA-87) | 2592 bytes     | 4896 bytes      | 4627 bytes     |

**API Highlights** (Security levels: 2, 3, 5):
- `CryptoFactory.CreateDilithium(level)`: Returns ISigner instance (level: 2, 3, or 5).
- `ISigner.GenerateKeyPair()`: Returns (publicKey, privateKey).
- `ISigner.Sign(byte[] message, byte[] privateKey)`: Returns signature.
- `ISigner.Verify(byte[] message, byte[] signature, byte[] publicKey)`: Returns bool.
- `ISigner.GetSignatureLength()`: Expected sig size.

**Example** (using level 5):
```csharp
using GreenfieldPQC.Cryptography;

var signer = CryptoFactory.CreateDilithium(5);
var (pubKey, privKey) = signer.GenerateKeyPair();
byte[] message = Encoding.UTF8.GetBytes("Sign me");
byte[] sig = signer.Sign(message, privKey);
bool valid = signer.Verify(message, sig, pubKey);  // true
```

**Best Practices**: Hash messages first if large; use for certificates or code signing.

## Kusumi512

Kusumi512 is a post-quantum symmetric encryption algorithm that is designed to be secure against quantum attacks. It is a 512-bit key algorithm, meaning it uses a 512-bit key for encryption and decryption. This provides a high level of security, making it suitable for protecting sensitive data in a post-quantum world.

Kusumi512 is a symmetric encryption algorithm, meaning it uses the same key for both encryption and decryption. This is in contrast to asymmetric algorithms like Kyber and Dilithium, which use different keys for encryption and decryption.

Kusumi512 is designed to be efficient and secure, making it a good choice for applications that require strong encryption in a post-quantum environment.

It is also a stream cipher and boasts a 64-bit block counter. This makes it suitable to encrypt and decrypt streams, including long ones*.

(*If you stream 4K video and depend on a 32-bit block counter, you may need to reset your system in less than 72 hours; often daily, or every other day.)

**API Highlights**:
- `CryptoFactory.CreateKusumi512(byte[] key, byte[] nonce)`: Creates an `ISymmetricCipher` instance (key: 64 bytes, nonce: 12 bytes).
- `ISymmetricCipher.Encrypt(byte[] plaintext)`: Returns ciphertext (stream mode).
- `ISymmetricCipher.Decrypt(byte[] ciphertext)`: Returns plaintext.
- `ISymmetricCipher.EncryptInPlace(Span<byte> data)`: In-place encryption for performance.
- `ISymmetricCipher.DecryptInPlace(Span<byte> data)`: Symmetric to above.
- `ISymmetricCipher.EncryptStream(Stream input, Stream output, int bufferSize=4096, Func<long, byte[]>? nonceGenerator=null)`: Stream encryption.
- `ISymmetricCipher.DecryptStream(Stream input, Stream output, int bufferSize=4096, Func<long, byte[]>? nonceGenerator=null)`: Stream decryption.
- `ISymmetricCipher.EncryptAsync/DecryptAsync`: Task-wrapped with cancellation.
- `ISymmetricCipher.EncryptInPlaceAsync/DecryptInPlaceAsync`: Memory<byte> versions with cancellation.
- `ISymmetricCipher.EncryptStreamAsync/DecryptStreamAsync`: With progress, cancellation, async nonceGen.

**Example**:
```csharp
using GreenfieldPQC.Cryptography;
using System.Security.Cryptography;

// Generate key and nonce
byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);

ISymmetricCipher cipher = CryptoFactory.CreateKusumi512(key, nonce);
byte[] plaintext = Encoding.UTF8.GetBytes("Hello, quantum-safe world!");
byte[] ciphertext = cipher.Encrypt(plaintext);
byte[] decrypted = cipher.Decrypt(ciphertext);  // Matches plaintext
```

**Best Practices**: Use unique nonces per session; rotate keys frequently. For benchmarks, see repo's BENCHMARKS.md.

## Kusumi512Poly1305

Kusumi512Poly1305 is an authenticated encryption with associated data (AEAD) mode that combines the Kusumi512 symmetric cipher with the Poly1305 message authentication code (MAC). This integration provides both confidentiality (via encryption) and integrity/authenticity (via MAC), ensuring that encrypted data cannot be tampered with undetected.

Like Kusumi512, it uses a 512-bit key and is designed for post-quantum security, offering resistance against quantum threats such as Grover's algorithm. It is particularly useful for secure messaging, file storage, or any scenario where data integrity is as critical as secrecy.

In the developer API, Kusumi512Poly1305 supports streaming operations and is efficient for high-throughput applications, aligning with the performance advantages seen in Kusumi512 benchmarks.

**API Highlights**:
- `CryptoFactory.CreateKusumi512Poly1305(byte[] key, byte[] nonce)`: Creates an `ISymmetricCipher` instance (key: 64 bytes, nonce: 12 bytes).
- `ISymmetricCipher.Encrypt(byte[] plaintext)`: Returns ciphertext + tag.
- `ISymmetricCipher.Decrypt(byte[] ciphertextWithTag)`: Returns plaintext or throws on tamper.
- Note that EncryptInPlace (and DecryptInPlace) are not supported in the Poly1305 version of Kusumi512.

**Example**:
```csharp
using GreenfieldPQC.Cryptography;
using System.Security.Cryptography;

byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);

ISymmetricCipher cipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
byte[] plaintext = Encoding.UTF8.GetBytes("Authenticated data");
byte[] ciphertextWithTag = cipher.Encrypt(plaintext);
byte[] decrypted = cipher.Decrypt(ciphertextWithTag);  // Matches plaintext
```

**Best Practices**: Always verify integrity via the combined tag; include timestamps in data to prevent replays.

## SHA256

SHA256 is a cryptographic hash function from the SHA-2 family that produces a 256-bit (32-byte) fixed-size digest from input data of any size. It is widely used for data integrity verification, digital signatures, and as a building block in key derivation functions.

In the context of the GreenfieldPQC toolkit, SHA256 serves as a reliable "old normal" hash for scenarios where a 256-bit output is sufficient, such as hashing messages before signing with Dilithium or deriving intermediate values. While quantum computers may reduce its effective security via Grover's algorithm, it remains suitable for many applications when combined with post-quantum primitives, especially as a faster alternative to SHA512 for non-key-derivation tasks.

The implementation leverages .NET's built-in System.Security.Cryptography for efficiency and compatibility.

**API Highlights**:
- `CryptoFactory.CreateSHA256()`: Returns reusable SHA256 instance.
- `CryptoFactory.ComputeSHA256(byte[] data)`: Static one-off hash.

**Example**:
```csharp
// Instance (reusable, thread-safe for ComputeHash)
using var sha256 = CryptoFactory.CreateSHA256();
byte[] hash = sha256.ComputeHash(data);  // Or sha256.ComputeHash(stream)
```

## SHA512

SHA512 is a cryptographic hash function from the SHA-2 family that generates a 512-bit (64-byte) fixed-size digest. It offers higher security margins than SHA256, making it ideal for deriving longer keys or handling larger security requirements.

Within GreenfieldPQC, SHA512 is particularly valuable for post-quantum workflows, such as hashing Kyber's 256-bit shared secret to produce a 512-bit key for Kusumi512 encryption. This ensures both parties can independently derive the same symmetric key without transmission. Its quantum resistance stems from the hash length, providing effective 256-bit security against Grover's algorithm for preimage attacks.

Like SHA256, it uses .NET's native System.Security.Cryptography implementation for optimal performance and seamless integration.

**API Highlights**:
- `CryptoFactory.CreateSHA512()`: Returns reusable SHA512 instance.
- `CryptoFactory.ComputeSHA512(byte[] data)`: Static one-off hash.

**Example**:
```csharp
// Instance (reusable, thread-safe for ComputeHash)
using var sha512 = CryptoFactory.CreateSHA512();
byte[] hash = sha512.ComputeHash(data);  // Or sha512.ComputeHash(stream)
```

## Cross Cutting Concerns

Namespace: `GreenfieldPQC.Cryptography`

### CryptoFactory
Static factory for keys, nonces, and instances.

- **GenerateKey(CipherAlgorithm alg)**: Random key.
  - `Kusumi512`/`Kusumi512Poly1305`: 64 bytes.
  - `Kyber`/`Dilithium`: Algorithm-specific (use CreateKyber/CreateDilithium for instantiation).
  - Example: `byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);`

- **GenerateNonce(CipherAlgorithm alg)**: Random nonce (12 bytes for Kusumi).
  - Example: `byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);`

- **CreateKusumi512(byte[] key, byte[] nonce)**: Kusumi512 instance.
- **CreateKusumi512Poly1305(byte[] key, byte[] nonce)**: AEAD instance.
- **CreateKyber(int level)**: Returns IKeyEncapsulationMechanism (level: 512, 768, 1024).
- **CreateDilithium(int level)**: Returns ISigner (level: 2, 3, 5).
- **CreateSHA256()**: Returns SHA256 instance.
- **CreateSHA512()**: Returns SHA512 instance.
- **CreateHash(HashAlgorithmType type)**: Returns IHashAlgorithm (type: SHA256, SHA512).

- **ComputeSHA256(byte[] data)**: SHA-256 hash.
- **ComputeSHA512(byte[] data)**: SHA-512 hash.
  - Example: `byte[] hash = CryptoFactory.ComputeSHA512(data);`

Supported Algorithms (Enum: `CipherAlgorithm`): Kusumi512, Kusumi512Poly1305, Kyber, Dilithium, SHA256, SHA512.

### IKeyEncapsulationMechanism (for Kyber)
Interface for key encapsulation operations (useful for mocking/testing).

- **GenerateKeyPair()**: Returns (publicKey, privateKey) tuple.
- **Encapsulate(byte[] publicKey)**: Returns (sharedSecret, ciphertext) tuple.
- **Decapsulate(byte[] ciphertext, byte[] privateKey)**: Returns sharedSecret.

### ISigner (for Dilithium)
Interface for digital signing operations (useful for mocking/testing).

- **GenerateKeyPair()**: Returns (publicKey, privateKey) tuple.
- **Sign(byte[] message, byte[] privateKey)**: Returns signature.
- **Verify(byte[] message, byte[] signature, byte[] publicKey)**: Returns bool indicating validity.
- **GetSignatureLength()**: Returns expected signature size in bytes.

### ISymmetricCipher (for Kusumi512/Kusumi512Poly1305)
Interface for symmetric ops (useful for mocking/testing).

- **AlgorithmName**: String property (e.g., "Kusumi512").
- **Encrypt(byte[] plaintext)**: Returns ciphertext (with tag for AEAD).
- **Decrypt(byte[] ciphertext)**: Returns plaintext (verifies tag for AEAD).
- **EncryptAsync/DecryptAsync**: Task-wrapped with cancellation.
- **EncryptInPlace(Span<byte> io)**: In-place (not for AEAD).
- **DecryptInPlace(Span<byte> io)**: Symmetric to above.
- **EncryptInPlaceAsync/DecryptInPlaceAsync**: Memory<byte> versions with cancellation.
- **EncryptStream(Stream in, Stream out, int buf=4096, Func<long, byte[]>? nonceGen=null)**: Stream encryption.
- **DecryptStream**: Stream decryption.
- **EncryptStreamAsync/DecryptStreamAsync**: With progress, cancellation, async nonceGen.

For AEAD: Ciphertext appends 128-bit tag; decryption throws on invalid.

### IHashAlgorithm (for SHA256/SHA512)
Interface for hash operations (useful for mocking/testing).

- **ComputeHash(byte[] data)**: Returns hash digest for byte array input.
- **ComputeHash(Stream stream)**: Returns hash digest for stream input.
