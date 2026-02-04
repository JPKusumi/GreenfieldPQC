using System;

namespace GreenfieldPQC.Cryptography
{
    /// <summary>
    /// Provides methods for creating and verifying JSON Web Signature (JWS) tokens using post-quantum primitives.
    /// </summary>
    public interface IJwsProvider
    {
        /// <summary>
        /// Creates a compact JWS token from the given payload using the private key.
        /// </summary>
        /// <param name="payload">The object to serialize as the payload.</param>
        /// <param name="privateKey">The private key for signing (e.g., ML-DSA/Dilithium).</param>
        /// <returns>The compact JWS string (three-part format).</returns>
        string CreateJws(object payload, byte[] privateKey);

        /// <summary>
        /// Verifies a JWS token using the public key and returns the deserialized payload if valid.
        /// </summary>
        /// <param name="jwsToken">The compact JWS string to verify.</param>
        /// <param name="publicKey">The public key for verification.</param>
        /// <returns>The deserialized payload object if valid; throws on failure.</returns>
        object VerifyJws(string jwsToken, byte[] publicKey);
    }
}