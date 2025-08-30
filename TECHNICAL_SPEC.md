# Kusumi-512 Stream Cipher

## Abstract

This document describes Kusumi-512, a stream cipher designed for high-performance symmetric encryption in post-quantum cryptography contexts. Kusumi-512 provides a 256-bit security level against classical attacks and is optimized for software implementations on platforms without specialized hardware acceleration. It is intended as a drop-in alternative to existing stream ciphers like ChaCha20, offering comparable speed with an enlarged state for future-proofing. This specification includes the algorithm description, test vectors, and security considerations.

This document represents a standalone specification and is not an IETF standard.

## Status of This Memo

This document is an independent submission and does not represent an Internet Standards Track specification. It is provided for informational purposes only.

## Table of Contents

1.  Introduction  
    1.1.  Conventions Used in This Document  
2.  The Kusumi-512 Algorithm  
    2.1.  The Kusumi Quarter Round  
        2.1.1.  Test Vector for the Kusumi Quarter Round  
    2.2.  A Quarter Round on the Kusumi State  
        2.2.1.  Test Vector for the Quarter Round on the Kusumi State  
    2.3.  The Kusumi-512 Block Function  
        2.3.1.  The Kusumi-512 Block Function in Pseudocode  
        2.3.2.  Test Vector for the Kusumi-512 Block Function  
    2.4.  The Kusumi-512 Encryption Algorithm  
        2.4.1.  The Kusumi-512 Encryption Algorithm in Pseudocode  
        2.4.2.  Example and Test Vector for the Kusumi-512 Cipher  
3.  Implementation Advice  
4.  Security Considerations  
5.  References  
    5.1.  Normative References  
    5.2.  Informative References  
Appendix A.  Additional Test Vectors  
Appendix B.  Performance Measurements of Kusumi-512  
Acknowledgements  
Authors' Addresses  

## 1. Introduction

Stream ciphers play a critical role in symmetric encryption, providing efficient confidentiality for data in transit and at rest. While algorithms like AES-CTR and ChaCha20 have dominated due to their security and performance, emerging threats from quantum computing and the need for higher throughput in software environments motivate the development of new primitives.

Kusumi-512 is a stream cipher based on the ARX (Addition-Rotation-XOR) design paradigm, extending principles from ChaCha20 and Skein/Threefish to achieve an enlarged 800-bit state for enhanced diffusion and resistance to cryptanalysis. It uses a 512-bit key and a 96-bit nonce, producing a keystream that can be XORed with plaintext to generate ciphertext. Kusumi-512 is designed to be timing-attack resistant, parallelizable, and performant on general-purpose CPUs, making it suitable for post-quantum hybrid schemes in libraries like GreenfieldPQC.

Recent optimizations, including a reduction from 12 to 10 rounds, have improved performance while preserving security margins comparable to ChaCha12. This document specifies the optimized Kusumi-512 in detail, enabling interoperable implementations. It does not define an authenticated encryption mode but can be combined with authenticators like Poly1305.

### 1.1. Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

The Kusumi state is represented as a 25-word vector of 32-bit unsigned integers, indexed from 0 to 24. All additions are modulo 2^32, rotations are left rotations (<<<), and XOR is denoted as ^. Constants are given in hexadecimal.

## 2. The Kusumi-512 Algorithm

Kusumi-512 operates on an 800-bit state (25 words of 32 bits each). It applies 10 iterations of mixing, each consisting of multiple quarter rounds, similar to ChaCha20 but adapted for the larger state, 512-bit key, and 64-bit block counter.

### 2.1. The Kusumi Quarter Round

The basic operation is the quarter round on four 32-bit words a, b, c, d:

a += b; d ^= a; d <<<= 16;  
c += d; b ^= c; b <<<= 12;  
a += b; d ^= a; d <<<= 8;  
c += d; b ^= c; b <<<= 7;  

#### 2.1.1. Test Vector for the Kusumi Quarter Round

Input:  
a = 0x11111111  
b = 0x01020304  
c = 0x090a0b0c  
d = 0x11121314  

Output:  
a = 0xa2e3a525  
b = 0x30d1d131  
c = 0xf2b132b2  
d = 0xe2a624a5  

### 2.2. A Quarter Round on the Kusumi State

The state is treated as a 25-word vector. Each iteration applies quarter rounds in a specific pattern to cover all words:

QR(0, 4, 8, 12)  
QR(1, 5, 9, 13)  
QR(2, 6, 10, 14)  
QR(3, 7, 11, 15)  
QR(16, 20, 0, 4)  
QR(17, 21, 1, 5)  
QR(18, 22, 2, 6)  
QR(19, 23, 3, 7)  
QR(0, 5, 10, 15)  
QR(1, 6, 11, 12)  
QR(2, 7, 8, 13)  
QR(3, 4, 9, 14)  
QR(16, 21, 2, 7)  
QR(17, 22, 3, 4)  
QR(18, 23, 0, 5)  
QR(19, 20, 1, 6)  
QR(19, 24, 0, 5)  // Covers the 25th word  

This pattern is repeated for 10 iterations.

#### 2.2.1. Test Vector for the Quarter Round on the Kusumi State

Initial State: [0x00000000, ... (all zeros, 25 words)]  

After One Iteration: (values can be derived from sequential QR applications; for brevity, see full block test below)  

### 2.3. The Kusumi-512 Block Function

The state is initialized with constants, key (16 words), 64-bit counter (2 words), nonce (3 words). 10 iterations are applied, then the keystream is the serialized state added (mod 2^32) to the initial state.

Constants:  
state[0] = 0x61707865 ("expa")  
state[1] = 0x3320646e ("nd 3")  
state[2] = 0x79622d32 ("2-by")  
state[3] = 0x6b206574 ("te k")  

#### 2.3.1. The Kusumi-512 Block Function in Pseudocode

state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;  
state[4..19] = key[0..15];  
state[20] = counter_low (uint);  
state[21] = counter_high (uint);  
state[22..24] = nonce[0..2];  
initial_state = copy(state);  
for y = 0 to 9:  
  QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);  
  QR(16, 20, 0, 4); QR(17, 21, 1, 5); QR(18, 22, 2, 6); QR(19, 23, 3, 7);  
  QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);  
  QR(16, 21, 2, 7); QR(17, 22, 3, 4); QR(18, 23, 0, 5); QR(19, 20, 1, 6);  
  QR(19, 24, 0, 5);  
for i = 0 to 24:  
  state[i] += initial_state[i];  
keystream = littleendian_serialize(state) [0..99];  // 100 bytes  

#### 2.3.2. Test Vector for the Kusumi-512 Block Function

Key: all zeros (512 bits)  
Nonce: all zeros (96 bits)  
Counter: 0 (64 bits)  
Keystream Block (hex):  
00 6e 79 1d 96 25 f8 11 2b 88 9e 79 a2 c2 d6 57 df 53 88 6a 1d bc 80 02 37 ef 71 c3 85 5b bf 1a e8 ee 8f c6 dc 2d fe e9 b5 7a 3b 31 fa c0 5f 13 3c ee 50 f5 6e 6a 8d 20 eb d5 a8 47 5c cf 8b c3 ee 10 b8 88 8e e9 11 36 9c 2f 88 aa 4b bc 5d 0c 1e bf 9b 6b b1 da 0f f1 14 0b 9f 55 40 08 c9 e5 3f 48 ab 06  

### 2.4. The Kusumi-512 Encryption Algorithm

Encryption XORs plaintext with keystream blocks, advancing the 64-bit counter as needed, starting at 1 (reserving 0 for associated data or key derivation).

#### 2.4.1. The Kusumi-512 Encryption Algorithm in Pseudocode

counter = 1 (64-bit)  
for each 100-byte block of plaintext:  
  keystream = block_function(key, nonce, counter)  
  ciphertext = plaintext ^ keystream  
  counter += 1  

#### 2.4.2. Example and Test Vector for the Kusumi-512 Cipher

Plaintext: "No man is an island, entire of itself; every man is a piece of the continent, a part of the main. If a clod be washed away by the sea, Europe is the less, as well as if a promontory were, as well as if a manor of thy friend's or of thine own were: any man's death diminishes me, because I am involved in mankind, and therefore never send to know for whom the bell tolls; it tolls for thee."  
  
Key: 0E:22:7B:32:86:79:AA:12:8A:A8:44:C3:D2:5A:79:ED:6D:DE:8C:FA:82:8E:99:7E:F7:56:BD:0B:4E:E4:37:38:70:44:B6:79:97:16:6D:45:04:C5:83:E8:64:B8:A3:3D:D1:A8:E0:83:4A:63:9A:6E:8B:B2:85:68:EE:85:EF:5F (64 bytes)  
  
Nonce: 99:27:A4:15:54:1D:83:41:63:A3:46:77 (12 bytes)  
  
Ciphertext (hex):  
C6:39:45:3F:06:41:00:04:DE:17:B6:B9:3A:C9:C9:D3:32:1E:41:46:64:24:44:E3:1C:35:96:74:A3:CE:1D:7E:42:C0:35:D1:DA:38:78:6B:04:3B:E9:C9:BF:28:0E:D7:8B:06:1C:49:02:A7:8C:57:C5:BD:6A:78:F7:00:CE:8F:B0:EF:22:35:24:ED:46:ED:70:70:75:58:97:B9:0A:38:91:E5:10:19:4A:95:F4:31:9B:60:DF:C6:D5:DD:11:85:19:B6:D5:0C:0A:42:E8:75:61:11:F7:06:80:76:12:76:1B:75:F8:AB:8E:61:2D:4F:20:CF:B8:95:99:32:36:72:0C:23:6D:64:E7:6A:77:7F:5B:0A:08:6D:9E:7F:EB:B0:A4:EC:EE:2C:C2:85:32:65:98:55:A9:D0:BD:51:94:92:81:4F:D4:88:65:4B:D9:8E:3A:C7:A0:3C:FF:C8:C1:17:72:15:E4:57:A1:B8:DD:AC:F2:27:C4:02:08:EE:DF:EA:05:0F:45:D9:9F:D4:B2:DD:2E:5A:C9:FE:F8:09:88:A0:49:EE:59:3D:0F:9E:29:12:85:10:46:55:AD:8E:A4:80:1E:4B:00:2B:9D:D8:52:C5:4F:D6:E3:F9:D4:E6:6E:94:7C:21:1D:4A:39:75:06:DA:0A:10:A4:2D:15:43:80:69:19:20:C9:BA:F1:4E:52:53:59:0F:A5:17:15:2F:0E:D4:35:61:6D:50:95:D0:5E:3A:61:9E:55:59:0F:71:09:21:BF:5C:B7:6B:9B:2A:A9:B8:8E:92:A9:0D:4E:19:5F:1B:AB:AA:8A:92:43:0E:C4:3F:56:BB:60:36:03:2D:6B:6C:D7:F4:86:42:33:1F:1E:B0:6D:F8:9D:3C:76:B2:39:4D:99:6A:2B:F6:FD:87:3B:47:53:0F:01:D2:51:7D:A6:C3:C6:93:7E:3D:C9:45:84:B9:5D:C6:3D:8E:2B:A1:1F:77:FB:DB:45:21:E0:75:C0:71:15:77:91:4B:6F:51:83:B8:E8:3C:FD:56:89


## 3. Implementation Advice

Implement in constant time to avoid timing attacks. Use 32-bit operations for efficiency. Parallelize rounds if possible. The enlarged state provides better security margins but may require careful memory management. The optimization to 10 rounds improves performance while maintaining a conservative security margin; implementations SHOULD use Unsafe pointers or equivalent for optimized state access in .NET environments.

## 4. Security Considerations

Kusumi-512 targets 256-bit security. Resistant to differential cryptanalysis via 10 iterations and larger state. Nonce reuse catastrophic. Key rotation recommended. The 64-bit counter mitigates overflow risks compared to 32-bit in ChaCha20. Reserve counter=0 for Poly1305 key generation in AEAD modes.

## 5. References

### 5.1. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017, <https://www.rfc-editor.org/info/rfc8174>.

### 5.2. Informative References

[RFC8439] Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols", RFC 8439, DOI 10.17487/RFC8439, June 2018, <https://www.rfc-editor.org/info/rfc8439>.

[Skein] Ferguson, N., et al., "The Skein Hash Function Family", Version 1.3, October 2010.

## Appendix A.  Additional Test Vectors

A.1. Kusumi-512 Block Functions  

[Additional hex inputs/outputs based on implementation, e.g., non-zero key/nonce]

## Appendix B.  Performance Measurements of Kusumi-512

On Intel i9-11900H with .NET 8: Kusumi-512 achieves ~6.4 μs for 1MB encryption (0.92x vs. Threefish-512), with ~2048 KB allocation (0.59x vs. Threefish). Python simulations show comparable efficiency, often faster than Threefish in pure-software contexts. See also, BENCHMARKS.md (of the same repo) for more performance measures.

## Acknowledgements

The cryptography community (h/t Daniel J. Bernstein) should be thanked for the inspiration of ChaCha20. The Linux Foundation’s Post-Quantum Cryptography Alliance must be thanked for liboqs, which is a bundled dependency of GreenfieldPQC. Thanks to the xAI team for the Grok contributions in this project. Thanks also to Microsoft for the Copilot assistance, and for "the stack" — C#, .NET, Visual Studio, GitHub, and NuGet.

## Author's Address

John Kusumi  
Email: john.kusumi@greenfieldpqc.com