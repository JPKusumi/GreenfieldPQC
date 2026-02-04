using System;
using System.Text;
using System.Text.Json;

namespace GreenfieldPQC.Cryptography
{
    internal class JweProvider : IJweProvider
    {
        private readonly IKeyEncapsulationMechanism _kem;  // e.g., ML-KEM (Kyber)
        private readonly CryptoFactory.CipherAlgorithm _algorithm;  // To recreate cipher per token

        public JweProvider(IKeyEncapsulationMechanism kem, CryptoFactory.CipherAlgorithm algorithm)
        {
            _kem = kem ?? throw new ArgumentNullException(nameof(kem));
            _algorithm = algorithm;
        }

        public string CreateJwe(object payload, byte[] recipientPublicKey)
        {
            // Header with alg (ML-KEM) and enc (KUSUMI512-POLY1305)
            var header = new { alg = "ML-KEM-768", enc = "KUSUMI512-POLY1305" };  // Adjust levels
            string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));

            // Encapsulate with ML-KEM to generate shared secret (32 bytes) and ciphertext (encrypted key)
            var (sharedSecret, encryptedKey) = _kem.Encapsulate(recipientPublicKey);  // 1 arg: pubKey; returns sharedSecret, ciphertext (encryptedKey)

            // Derive 64-byte CEK from 32-byte sharedSecret using SHA-512
            byte[] cek = CryptoFactory.ComputeSHA512(sharedSecret);  // Expands to 64 bytes

            // Generate IV/nonce
            byte[] iv = CryptoFactory.GenerateNonce(CryptoFactory.CipherAlgorithm.Kusumi512);  // Use algorithm enum; assumes it returns appropriate size

            // Recreate cipher with per-token key/iv
            ISymmetricCipher cipher = _algorithm == CryptoFactory.CipherAlgorithm.Kusumi512Poly1305
                ? CryptoFactory.CreateKusumi512Poly1305(cek, iv)
                : CryptoFactory.CreateKusumi512(cek, iv);

            // Serialize and encrypt payload
            byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
            byte[] ciphertextAndTag = cipher.Encrypt(payloadBytes);  // Returns ciphertext + tag

            // Handle split with check for short/empty
            byte[] ciphertextArr;
            byte[] authTagArr;
            if (ciphertextAndTag.Length < 16)
            {
                ciphertextArr = new byte[0];
                authTagArr = ciphertextAndTag;  // Full is tag for empty cases
            }
            else
            {
                ciphertextArr = new byte[ciphertextAndTag.Length - 16];
                authTagArr = new byte[16];
                Array.Copy(ciphertextAndTag, 0, ciphertextArr, 0, ciphertextArr.Length);
                Array.Copy(ciphertextAndTag, ciphertextArr.Length, authTagArr, 0, authTagArr.Length);
            }

            // Assemble compact JWE
            return $"{encodedHeader}.{Base64UrlEncode(encryptedKey)}.{Base64UrlEncode(iv)}.{Base64UrlEncode(ciphertextArr)}.{Base64UrlEncode(authTagArr)}";
        }

        public string DecryptJwe(string jweToken, byte[] recipientPrivateKey)
        {
            string[] parts = jweToken.Split('.');
            if (parts.Length != 5) throw new ArgumentException("Invalid JWE format");

            byte[] encryptedKey = Base64UrlDecode(parts[1]);
            byte[] iv = Base64UrlDecode(parts[2]);
            byte[] ciphertext = Base64UrlDecode(parts[3]);
            byte[] authTag = Base64UrlDecode(parts[4]);

            // Decapsulate to get shared secret (32 bytes)
            byte[] sharedSecret = _kem.Decapsulate(encryptedKey, recipientPrivateKey);  // 2 args: ciphertext (encryptedKey), privKey

            // Derive 64-byte CEK from 32-byte sharedSecret using SHA-512
            byte[] cek = CryptoFactory.ComputeSHA512(sharedSecret);  // Expands to 64 bytes

            // Recreate cipher with per-token key/iv
            ISymmetricCipher cipher = _algorithm == CryptoFactory.CipherAlgorithm.Kusumi512Poly1305
                ? CryptoFactory.CreateKusumi512Poly1305(cek, iv)
                : CryptoFactory.CreateKusumi512(cek, iv);

            // Concat ciphertext + tag for decrypt
            byte[] ciphertextAndTag = new byte[ciphertext.Length + authTag.Length];
            Array.Copy(ciphertext, 0, ciphertextAndTag, 0, ciphertext.Length);
            Array.Copy(authTag, 0, ciphertextAndTag, ciphertext.Length, authTag.Length);

            // Decrypt
            byte[] payloadBytes = cipher.Decrypt(ciphertextAndTag);  // Returns plaintext or throws on tamper

            // Get the decrypted JSON string
            string jsonString = Encoding.UTF8.GetString(payloadBytes);
            
            // If the payload was a string (like a nested JWS token), it will be JSON-serialized with quotes
            // We need to deserialize it to get the original string back
            // Check if it's a JSON string literal (starts and ends with quotes, after trimming whitespace)
            string trimmed = jsonString.Trim();
            if (trimmed.StartsWith("\"") && trimmed.EndsWith("\""))
            {
                // It's a JSON string literal, deserialize to get the actual string
                return JsonSerializer.Deserialize<string>(jsonString) 
                       ?? throw new InvalidOperationException("Deserialization returned null");
            }
            else
            {
                // It's a JSON object or other type, return the raw JSON string
                return jsonString;
            }
        }

        // Utilities (add to a helper class if not existing)
        private static string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        private static byte[] Base64UrlDecode(string input) => Convert.FromBase64String(input.Replace("-", "+").Replace("_", "/") + new string('=', (4 - input.Length % 4) % 4));
    }
}