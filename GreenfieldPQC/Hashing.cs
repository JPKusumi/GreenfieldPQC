using System;
using System.IO;

namespace GreenfieldPQC.Cryptography
{
    public interface IHashAlgorithm : IDisposable
    {
        byte[] ComputeHash(byte[] data);
        byte[] ComputeHash(Stream stream);
    }
    public enum HashAlgorithmType { SHA256, SHA512 }

    /// <summary>
    /// SHA-256 hash function, matching Microsoft's API.
    /// Instances are not thread-safe for concurrent use.
    /// </summary>
    public sealed class SHA256 : IHashAlgorithm
    {
        private readonly System.Security.Cryptography.SHA256 _sha256;

        private SHA256()
        {
            _sha256 = System.Security.Cryptography.SHA256.Create();
        }

        public static SHA256 Create() => new SHA256();

        public byte[] ComputeHash(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return _sha256.ComputeHash(input);
        }

        public byte[] ComputeHash(Stream input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return _sha256.ComputeHash(input);
        }

        public void Dispose()
        {
            _sha256?.Dispose();
        }
    }

    /// <summary>
    /// SHA-512 hash function, matching Microsoft's API.
    /// Instances are not thread-safe for concurrent use.
    /// </summary>
    public sealed class SHA512 : IHashAlgorithm
    {
        private readonly System.Security.Cryptography.SHA512 _sha512;

        private SHA512()
        {
            _sha512 = System.Security.Cryptography.SHA512.Create();
        }

        public static SHA512 Create() => new SHA512();

        public byte[] ComputeHash(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return _sha512.ComputeHash(input);
        }

        public byte[] ComputeHash(Stream input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return _sha512.ComputeHash(input);
        }

        public void Dispose()
        {
            _sha512?.Dispose();
        }
    }
}
