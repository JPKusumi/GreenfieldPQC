using System;

namespace GreenfieldPQC.Cryptography
{
    /// <summary>
    /// Provides methods for creating and decrypting JSON Web Encryption (JWE) tokens using post-quantum primitives.
    /// </summary>
    public interface IJweProvider
    {
        /// <summary>
        /// Creates a compact JWE token from the given payload using the recipient's public key.
        /// </summary>
        /// <param name="payload">The object or string to serialize and encrypt as the payload.</param>
        /// <param name="recipientPublicKey">The recipient's public key for key encapsulation (e.g., ML-KEM).</param>
        /// <returns>The compact JWE string (five-part format).</returns>
        string CreateJwe(object payload, byte[] recipientPublicKey);

        /// <summary>
        /// Decrypts a JWE token using the recipient's private key and returns the raw decrypted payload as string.
        /// </summary>
        /// <param name="jweToken">The compact JWE string to decrypt.</param>
        /// <param name="recipientPrivateKey">The recipient's private key for decapsulation.</param>
        /// <returns>The raw decrypted payload string (JSON).</returns>
        string DecryptJwe(string jweToken, byte[] recipientPrivateKey);
    }
}