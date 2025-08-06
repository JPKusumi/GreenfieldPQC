# GreenfieldPQC
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet Version](https://img.shields.io/nuget/v/GreenfieldPQC.svg)](https://www.nuget.org/packages/GreenfieldPQC/)  
NuGet URL - https://www.nuget.org/packages/GreenfieldPQC  
GitHub URL - https://github.com/JPKusumi/GreenfieldPQC

## Overview: Quantum Resistance Available Now  

The world faces the threat of quantum computers with the ability to break current (or old normal) cryptographic systems. To use Post Quantum Cryptography (PQC) will become the new normal. GreenfieldPQC is a .NET library that provides post-quantum cryptographic primitives to secure applications against these future threats. It offers an opinionated subset drawn from available implementations of key encapsulation mechanisms (KEMs), symmetric encryption, digital signatures, and hashing algorithms designed to be resistant to quantum attacks. The goal is to sidestep threats like Grover's algorithm for symmetric ciphers and Shor's for asymmetric ones.  

The subset covers the bases to enable quantum safety from end-to-end. Combine components, e.g., use Kyber for key exchange, Kusumi512 for bulk encryption, Dilithium for signing, and SHA512 for hashing. Use CryptoFactory.GenerateKey and GenerateNonce for secure random generation. Note that Kusumi512 comes in two varieties (Kusumi512 and Kusumi512Poly1305, a MAC version to enable AEAD operation), and that two versions of hashing are included (SHA256 and SHA512).  

Where the old normal was to use 256-bit keys and hashes, the new normal is to use 512-bit keys and hashes. This library provides a simple way to implement this new normal in .NET applications.  

Hence, a key feature of the new normal is that devs and storage systems must accomodate larger data sizes for keys and hashes. While 256 bits is 32 bytes, 512 bits is 64 bytes.  

Package note. This package is best for green field development � new projects, not legacy systems. Corporate, legacy systems need more than code; database schemas may need to change, and they may choose to re-encrypt vulnerable data. Conversely, if you are on a green field project, then you can drop in this package and go. The name, GreenfieldPQC, indicates that brown field redevelopment on legacy systems is out of scope for this package.  

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
- **Efficiency**: Optimized for .NET (C#), with low overhead�ideal for high-throughput apps like cloud services, IoT, or data pipelines.  
- **Ease of Adoption**: NuGet integration; bundles oqs.dll for native PQC support (via P/Invoke for Kyber and Dilithium); requires .NET 8+.  
- **Risk Mitigation**: Addresses media "drumbeat" on quantum threats; supports compliance (e.g., FIPS-like standards pending NIST finalization).  
- **Benchmarks Summary**: From BENCHMARKS.md (in repo root), Kusumi512 excels in speed and RAM vs. alternatives, making it a practical "new normal" for 512-bit symmetric crypto.  

Evaluate via a proof-of-concept: Install the package and test Kusumi512 for your workload. For ROI, consider avoided breaches in a post-quantum world�contact NIST or consult [xAI's resources](https://x.ai) for broader AI/quantum insights.  

Resources:
- **Cryptography Basics**: [Wikipedia: Cryptography](https://en.wikipedia.org/wiki/Cryptography) � A high-level intro to encryption concepts.  
- **Symmetric vs. Asymmetric Encryption**: [Khan Academy: Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography) � Free videos explaining keys, ciphers, and hashes.  
- **Quantum Threats**: [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) � Explains why quantum computers could break current encryption and the shift to PQC.  
- **Quantum Computing Primer**: [IBM: What is Quantum Computing?](https://www.ibm.com/topics/quantum-computing) � Simple explanation of the "quantum threat" in news stories.  
- **Why Larger Keys Matter**: [Cloudflare: Post-Quantum Cryptography](https://blog.cloudflare.com/post-quantum-cryptography/) � Real-world context on urgency without deep math.  

## End-to-End Example  

Alice and Bob are old friends who love sharing secrets, but in this digital age, they're paranoid about eavesdroppers�like quantum computers that could one day crack traditional key exchanges. Alice wants to send Bob some confidential photos from their latest adventure, but she needs a super-secure way to encrypt them using her new favorite symmetric cipher, Kusumi512, which requires a 512-bit shared key. The problem? They don't have a secure way to agree on that key over the internet without someone intercepting it.

Enter Kyber, the post-quantum hero of key encapsulation mechanisms (KEMs). It's like a magical lockbox that's safe even from future quantum villains. Here's how their story unfolds:

1. **Alice Prepares the Lockbox**: Alice generates a Kyber key pair on her computer�a public key (like an open lock anyone can see) and a private key (the secret code to unlock it). She sends the public key to Bob over the open internet. No worries if someone like Eve intercepts it; the public key is useless without the private one.

2. **Bob Seals the Secret**: Bob receives Alice's public key and decides on a random shared secret (this will become their 512-bit Kusumi512 key). Using Kyber, he "encapsulates" this secret inside a ciphertext�a digital envelope sealed with Alice's public key. Only Alice can open it. Bob sends this ciphertext back to Alice.

3. **Alice Unlocks the Secret**: Alice uses her private key to "decapsulate" the ciphertext, revealing the exact shared secret Bob chose. Now both Alice and Bob have the same 512-bit key, and Eve (even with a quantum computer) can't figure it out because Kyber's lattice-based math is too tricky for Shor's algorithm.

4. **Symmetric Bliss with Kusumi512**: With the shared key in hand, Alice encrypts her photos using Kusumi512 in a mode like CTR (counter mode) for fast streaming. For extra security, she adds authentication with Poly1305, creating an AEAD (Authenticated Encryption with Associated Data) tag to ensure the data isn't tampered with. She sends the encrypted photos and tag to Bob.

5. **Bob Decrypts and Enjoys**: Bob uses the same shared Kusumi512 key to decrypt the photos and verify the Poly1305 tag. If everything checks out, he sees the images perfectly. If not, he knows something's fishy.

In the end, Alice and Bob's communication is quantum-safe from the start (thanks to Kyber) and blazing fast for the bulk data (thanks to Kusumi512's efficiency). This hybrid approach�post-quantum key exchange plus symmetric encryption�is the gold standard for future-proofing, enabled by this GreenfieldPQC toolkit for .NET developers. If quantum threats escalate, they're ready!

### How to Implement the End-to-End Example  

To implement the Alice and Bob scenario in C#, we'll use Kyber for quantum-safe key exchange, SHA512 to derive a 512-bit symmetric key from Kyber's 256-bit shared secret, and Kusumi512Poly1305 for authenticated bulk encryption (AEAD mode). This ensures confidentiality, integrity, and authenticity.  

Assume Alice and Bob have a way to exchange data (e.g., via files or a network channel�out of scope here). We'll use level 1024 for Kyber (high security) and focus on synchronous methods for simplicity. Use using statements for disposal.  

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
- Use secure channels for exchanges if possible, but Kyber ensures the shared secret is safe even over insecure ones.  
- For files/streams: Replace byte arrays with EncryptStreamAsync/DecryptStreamAsync for large data like photos.  
- Verify equality of shared secrets with CryptographicOperations.FixedTimeEquals in tests.  
- Rotate nonces/keys per session; include timestamps in data for replay protection.  
- Error handling: Wrap in try-catch for exceptions like invalid tags.  

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

Kyber is a post-quantum key encapsulation mechanism (KEM) standardized by NIST as ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) under FIPS 203 in August 2024. It provides secure key exchange resistant to quantum attacks. In the GreenfieldPQC API, it is referred to as Kyber, with implementation details relying on P/Invoke to a native DLL from liboqs as a transitive dependency.

### In Theory

A key encapsulation mechanism (KEM) is a cryptographic primitive that enables two parties to securely establish a shared secret key over an insecure channel without transmitting the key itself. Unlike traditional key exchange methods like Diffie-Hellman, which are vulnerable to quantum computers via Shor's algorithm, Kyber uses lattice-based problems that remain hard for quantum adversaries.

In practice, one party (the sender) uses the recipient's public key to generate a shared secret and a ciphertext (encapsulated key). The recipient then uses their private key to decapsulate the ciphertext and recover the same shared secret. The output is typically a 32-byte (256-bit) shared secret, which can be hashed (e.g., with SHA512) to derive longer symmetric keys. Key sizes vary by security level: for level 512, public keys are 800 bytes, private keys 1632 bytes, and ciphertexts 768 bytes; for 768, they are 1184, 2400, and 1088 bytes; for 1024, 1568, 3168, and 1568 bytes.

Common use cases include establishing session keys for secure communication protocols, replacing classical methods like ECDH in TLS handshakes, or bootstrapping symmetric encryption in hybrid cryptosystems. This ensures forward secrecy and quantum resistance for applications like secure messaging or VPNs.

### In Practice

**API Highlights** (Security levels: 512, 768, 1024):
- `CryptoFactory.CreateKyber(level)`: Returns IKeyEncapsulationMechanism instance.
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

Dilithium is a post-quantum digital signature algorithm standardized by NIST as ML-DSA (Module-Lattice-Based Digital Signature Algorithm) under FIPS 204 in August 2024. It ensures message authenticity and integrity against quantum threats. In the GreenfieldPQC API, it is referred to as Dilithium, with implementation via P/Invoke to a native DLL from liboqs as a transitive dependency.

### In Theory

A digital signature algorithm allows a signer to prove the authenticity and integrity of a message using a private key, while anyone with the corresponding public key can verify it. Dilithium, based on lattice problems, resists quantum attacks like those that break RSA or ECDSA with Shor's algorithm.

In practice, the signer generates a key pair, signs a message (or its hash) with the private key to produce a signature, and the verifier checks the signature against the message and public key. Signatures are fixed-size outputs varying by security level: for level 2 (ML-DSA-44), public keys are 1312 bytes, private keys 2560 bytes, and signatures 2420 bytes; for 3 (ML-DSA-65), 1952, 4032, and 3309 bytes; for 5 (ML-DSA-87), 2592, 4896, and 4627 bytes.

Use cases include signing software updates, certificates in PKI, or documents for non-repudiation, ensuring long-term security in scenarios like blockchain transactions or legal electronic signatures where quantum threats are a concern.

### In Practice

**API Highlights** (Security levels: 2, 3, 5):
- `CryptoFactory.CreateDilithium(level)`: Returns ISigner instance.
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

Kusumi512 is a post-quantum symmetric encryption algorithm using a 512-bit key, designed for efficiency and resistance to quantum attacks like Grover's algorithm. It operates as a stream cipher with a 64-bit block counter, suitable for encrypting large or streaming data.

### In Theory

Symmetric encryption uses the same key for both encryption and decryption, providing confidentiality by transforming plaintext into ciphertext that appears random without the key. Kusumi512, as a stream cipher, generates a keystream from the key and nonce, XORing it with the data for encryption (and decryption, since XOR is reversible).

In practice, inputs include a 64-byte key, a 12-byte nonce, and plaintext of any length; outputs are ciphertext of matching length. The 64-bit counter prevents nonce reuse issues over long streams, avoiding resets needed with shorter counters (e.g., in 4K video streaming, a 32-bit counter might require daily resets).

Use cases involve securing data at rest (e.g., file encryption) or in transit (e.g., streaming media), especially where high throughput is needed in quantum-safe environments like cloud storage or real-time communications.

### In Practice

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

Kusumi512Poly1305 is an authenticated encryption with associated data (AEAD) scheme combining Kusumi512 for confidentiality with Poly1305 for integrity, using a 512-bit key for post-quantum security.

### In Theory

AEAD primitives provide both encryption (confidentiality) and authentication (integrity and authenticity), detecting tampering or forgery. Kusumi512Poly1305 encrypts data while appending a MAC tag computed over the ciphertext.

In practice, inputs are a 64-byte key, 12-byte nonce, and plaintext; outputs include ciphertext plus a 16-byte tag. Decryption verifies the tag before returning plaintext, throwing an exception on failure. This prevents attacks like chosen-ciphertext or replay.

Use cases include secure messaging or file storage, where detecting modifications is crucial, such as in quantum-resistant protocols for IoT or financial transactions.

### In Practice

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

SHA256 is a cryptographic hash function from the SHA-2 family, producing a 256-bit digest. In GreenfieldPQC, it uses .NET's System.Security.Cryptography for compatibility, serving as a building block in hybrid post-quantum systems.

### In Theory

A hash function maps arbitrary input data to a fixed-size output (digest), ensuring that small changes in input produce vastly different outputs (avalanche effect). SHA256 is collision-resistant and preimage-resistant, though quantum computers reduce its effective security to about 128 bits via Grover's algorithm.

In practice, input is any byte array or stream; output is always 32 bytes. It's deterministic, so the same input always yields the same hash, enabling verification without storing originals.

Use cases include integrity checks (e.g., file downloads), message digests for signing with Dilithium, or password storage (with salting), often in workflows needing faster hashing than SHA512.

### In Practice

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

SHA512 is a cryptographic hash function from the SHA-2 family, producing a 512-bit digest. In GreenfieldPQC, it leverages .NET's System.Security.Cryptography, ideal for deriving longer keys in post-quantum contexts.

### In Theory

Hash functions like SHA512 provide a one-way transformation of data into a fixed digest, supporting integrity, authentication, and key derivation. With a longer output, it offers about 256-bit effective security against quantum preimage attacks via Grover's algorithm.

In practice, input can be any data; output is 64 bytes. It's used to expand shorter secrets (e.g., Kyber's 32-byte shared secret) into symmetric keys.

Use cases involve key derivation (e.g., hashing KEM outputs for Kusumi512), digital fingerprints for large files, or in HMAC for message authentication, ensuring robustness in quantum-hybrid cryptosystems.

### In Practice

**API Highlights**:
- `CryptoFactory.CreateSHA512()`: Returns reusable SHA512 instance.
- `CryptoFactory.ComputeSHA512(byte[] data)`: Static one-off hash.

**Example**:
```csharp
// Instance (reusable, thread-safe for ComputeHash)
using var sha512 = CryptoFactory.CreateSHA512();
byte[] hash = sha512.ComputeHash(data);  // Or sha512.ComputeHash(stream)
```

## API Documentation

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