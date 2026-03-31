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
        /// Creates a compact JWE token from raw payload bytes using the recipient's public key.
        /// Prefer this overload for sensitive payloads: the caller retains ownership of the byte array
        /// and may zero it after use. Unlike <see cref="CreateJwe(object, byte[])"/>, no intermediate
        /// JSON serialization string is produced from the provided bytes.
        /// </summary>
        /// <param name="payloadBytes">The raw bytes to encrypt as the JWE payload.</param>
        /// <param name="recipientPublicKey">The recipient's public key for key encapsulation (e.g., ML-KEM).</param>
        /// <returns>The compact JWE string (five-part format).</returns>
        /// <remarks>
        /// <b>Security note:</b> Never log the plaintext payload or any encryption key material.
        /// Strings in .NET are immutable and cannot be reliably zeroed; for the most sensitive payloads,
        /// keep data as <c>byte[]</c> and clear it with <see cref="Array.Clear"/> when finished.
        /// </remarks>
        string CreateJwe(ReadOnlySpan<byte> payloadBytes, byte[] recipientPublicKey);

        /// <summary>
        /// Decrypts a JWE token using the recipient's private key and returns the raw decrypted payload as string.
        /// </summary>
        /// <param name="jweToken">The compact JWE string to decrypt.</param>
        /// <param name="recipientPrivateKey">The recipient's private key for decapsulation.</param>
        /// <returns>The raw decrypted payload string (JSON).</returns>
        /// <remarks>
        /// <b>Security note:</b> The returned string is managed by the .NET runtime and cannot be
        /// reliably zeroed from memory. Do not log or include it in telemetry. If the ability to
        /// clear the plaintext from memory is required, use <see cref="DecryptJweBytes"/> instead.
        /// </remarks>
        string DecryptJwe(string jweToken, byte[] recipientPrivateKey);

        /// <summary>
        /// Decrypts a JWE token using the recipient's private key and returns the raw decrypted payload bytes.
        /// Prefer this overload over <see cref="DecryptJwe"/> when the caller needs to control the lifetime
        /// of the plaintext in memory: the returned <c>byte[]</c> can be zeroed with <see cref="Array.Clear"/>
        /// after use, unlike .NET strings which are immutable and cannot be reliably wiped.
        /// </summary>
        /// <param name="jweToken">The compact JWE string to decrypt.</param>
        /// <param name="recipientPrivateKey">The recipient's private key for decapsulation.</param>
        /// <returns>The raw decrypted payload bytes (UTF-8 encoded JSON or raw binary).</returns>
        /// <remarks>
        /// <b>Security note:</b> Never log the returned bytes or any key material. Zero the returned
        /// array with <see cref="Array.Clear"/> as soon as the plaintext is no longer needed.
        /// </remarks>
        byte[] DecryptJweBytes(string jweToken, byte[] recipientPrivateKey);
    }
}