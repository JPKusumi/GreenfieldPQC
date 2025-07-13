using System;
using System.Security.Cryptography;

namespace GreenfieldPQC.Cryptography
{
    public static class CryptoFactory
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        public enum CipherAlgorithm
        {
            Kusumi512,
            Kusumi512Poly1305,
            Kyber,
            Dilithium,
            SHA256,
            SHA512
        }

        public static byte[] GenerateKey(CipherAlgorithm algorithm)
        {
            return algorithm switch
            {
                CipherAlgorithm.Kusumi512 or CipherAlgorithm.Kusumi512Poly1305 => GenerateBytes(64), // 512-bit
                CipherAlgorithm.Kyber => GenerateBytes(32), // Placeholder; adjust for Kyber key size
                CipherAlgorithm.Dilithium => GenerateBytes(32), // Placeholder; adjust for Dilithium
                CipherAlgorithm.SHA256 or CipherAlgorithm.SHA512 => throw new InvalidOperationException("Hash algorithms do not require keys."),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
            };
        }

        public static byte[] GenerateNonce(CipherAlgorithm algorithm)
        {
            return algorithm switch
            {
                CipherAlgorithm.Kusumi512 or CipherAlgorithm.Kusumi512Poly1305 => GenerateBytes(12), // 96-bit
                _ => throw new InvalidOperationException("Nonce not applicable for this algorithm.")
            };
        }

        public static ISymmetricCipher CreateKusumi512(byte[] key, byte[] nonce)
        {
            return new Kusumi512(key, nonce);
        }

        public static ISymmetricCipher CreateKusumi512Poly1305(byte[] key, byte[] nonce)
        {
            return new Kusumi512Poly1305(key, nonce);
        }

        public static byte[] ComputeSHA256(byte[] data)
        {
            using var sha = new SHA256();
            return sha.HashSync(data);
        }

        public static byte[] ComputeSHA512(byte[] data)
        {
            using var sha = new SHA512();
            return sha.HashSync(data);
        }

        private static byte[] GenerateBytes(int length)
        {
            byte[] bytes = new byte[length];
            Rng.GetBytes(bytes);
            return bytes;
        }
    }
}