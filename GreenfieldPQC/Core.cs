using GreenfieldPQC.Cryptography.Parameters;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace GreenfieldPQC.Cryptography
{
    /// <summary>
    /// Interface for cryptographic primitives (base for ciphers and hashes).
    /// </summary>
    public interface ICryptoPrimitive : IDisposable
    {
        string AlgorithmName { get; }
    }

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
                CipherAlgorithm.Kyber => throw new InvalidOperationException("Kyber is asymmetric; use Kyber.GenerateKeyPair() instead."),
                CipherAlgorithm.Dilithium => throw new InvalidOperationException("Dilithium is asymmetric; use Dilithium.GenerateKeyPair() instead."),
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
            ArgumentNullException.ThrowIfNull(data);
            using SHA256 sha = SHA256.Create();
            return sha.ComputeHash(data);
        }

        public static byte[] ComputeSHA256(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);
            using SHA256 sha = SHA256.Create();
            return sha.ComputeHash(stream);
        }

        public static byte[] ComputeSHA512(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            using SHA512 sha = SHA512.Create();
            return sha.ComputeHash(data);
        }

        public static byte[] ComputeSHA512(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);
            using SHA512 sha = SHA512.Create();
            return sha.ComputeHash(stream);
        }

        private static byte[] GenerateBytes(int length)
        {
            byte[] bytes = new byte[length];
            Rng.GetBytes(bytes);
            return bytes;
        }
        public static IKeyEncapsulationMechanism CreateKyber(int level)
        {
            return new Kyber(new KyberParameters(level));
        }

        public static ISigner CreateDilithium(int level)
        {
            return new Dilithium(new DilithiumParameters(level));
        }

        public static SHA256 CreateSHA256()
        {
            return SHA256.Create();
        }

        public static SHA512 CreateSHA512()
        {
            return SHA512.Create();
        }

        public static IHashAlgorithm CreateHash(HashAlgorithmType type)
        {
            return type switch
            {
                HashAlgorithmType.SHA256 => SHA256.Create(),
                HashAlgorithmType.SHA512 => SHA512.Create(),
                _ => throw new ArgumentOutOfRangeException(nameof(type))
            };
        }
        public static IJweProvider CreateJweProvider(int kyberLevel = 3, CryptoFactory.CipherAlgorithm kusumiAlgorithm = CryptoFactory.CipherAlgorithm.Kusumi512)  // kyberLevel: 1 (512), 3 (768), 5 (1024); kusumiAlgorithm: Kusumi512 or Kusumi512Poly1305
        {
            int kyberParam = kyberLevel switch
            {
                1 => 512,
                3 => 768,
                5 => 1024,
                _ => throw new ArgumentOutOfRangeException(nameof(kyberLevel), "Must be 1, 3, or 5.")
            };
            var kem = CreateKyber(kyberParam);  // Pass the mapped parameter
            return new JweProvider(kem, kusumiAlgorithm);
        }
        public static IJwsProvider CreateJwsProvider(int dilithiumLevel = 3)  // Level: 2 (44), 3 (65), 5 (87)
        {
            var signer = CreateDilithium(dilithiumLevel);  // Existing factory for ML-DSA
            return new JwsProvider(signer);
        }
    }

    /// <summary>
    /// Interface for symmetric ciphers.
    /// </summary>
    public interface ISymmetricCipher : ICryptoPrimitive
    {
        Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default);
        byte[] Encrypt(byte[] plaintext);
        Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default);
        byte[] Decrypt(byte[] ciphertext);
        Task EncryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        void EncryptInPlace(Span<byte> inputOutput);
        Task DecryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        void DecryptInPlace(Span<byte> inputOutput);
        Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default);
        void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null);
        Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default);
        void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null);
    }

    /// <summary>
    /// Abstract base class for symmetric ciphers, handling key and nonce management.
    /// </summary>
    public abstract class SymmetricCipher(byte[] key, byte[] nonce) : ICryptoPrimitive, ISymmetricCipher
    {
        /// <summary>Gets the name of the cipher algorithm.</summary>
        public abstract string AlgorithmName { get; }
        /// <summary>Gets the encryption key.</summary>
        protected byte[] Key { get; } = key ?? throw new ArgumentNullException(nameof(key));
        /// <summary>Gets the nonce (number used once).</summary>
        protected byte[] Nonce { get; } = nonce ?? throw new ArgumentNullException(nameof(nonce));

        public abstract Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default);
        public abstract byte[] Encrypt(byte[] plaintext);
        public abstract Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default);
        public abstract byte[] Decrypt(byte[] ciphertext);
        public abstract Task EncryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        public abstract void EncryptInPlace(Span<byte> inputOutput);
        public abstract Task DecryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        public abstract void DecryptInPlace(Span<byte> inputOutput);

        public virtual async Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(output);
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long totalBytes = input.CanSeek ? input.Length : -1;
            long bytesProcessed = 0;
            int segmentCount = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (true)
            {
                int bytesRead = await input.ReadAsync(buffer.AsMemory(0, bufferSize), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    byte[] newNonce = await nonceGenerator(bytesProcessed).ConfigureAwait(false);
                    UpdateNonce(newNonce);
                    segmentProgress?.Report(++segmentCount);
                }

                await EncryptInPlaceAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                bytesProcessed += bytesRead;
                if (totalBytes > 0)
                    progress?.Report((double)bytesProcessed / totalBytes);
            }
        }

        public virtual void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(output);
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long bytesProcessed = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (input.Read(buffer, 0, bufferSize) is int bytesRead && bytesRead > 0)
            {
                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                EncryptInPlace(buffer.AsSpan(0, bytesRead));
                output.Write(buffer, 0, bytesRead);
                bytesProcessed += bytesRead;
            }
        }

        public virtual async Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(output);
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long totalBytes = input.CanSeek ? input.Length : -1;
            long bytesProcessed = 0;
            int segmentCount = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (true)
            {
                int bytesRead = await input.ReadAsync(buffer.AsMemory(0, bufferSize), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    byte[] newNonce = await nonceGenerator(bytesProcessed).ConfigureAwait(false);
                    UpdateNonce(newNonce);
                    segmentProgress?.Report(++segmentCount);
                }

                await DecryptInPlaceAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                bytesProcessed += bytesRead;
                if (totalBytes > 0)
                    progress?.Report((double)bytesProcessed / totalBytes);
            }
        }

        public virtual void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(output);
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long bytesProcessed = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (input.Read(buffer, 0, bufferSize) is int bytesRead && bytesRead > 0)
            {
                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                DecryptInPlace(buffer.AsSpan(0, bytesRead));
                output.Write(buffer, 0, bytesRead);
                bytesProcessed += bytesRead;
            }
        }

        /// <summary>Updates the nonce for ciphers requiring nonce changes. Use with caution to avoid nonce reuse.</summary>
        protected virtual void UpdateNonce(byte[] newNonce)
        {
            ArgumentNullException.ThrowIfNull(newNonce);
            Array.Clear(Nonce, 0, Nonce.Length);
            Array.Copy(newNonce, Nonce, Math.Min(newNonce.Length, Nonce.Length));
        }

        /// <summary>Clears sensitive data (key and nonce) and disposes the cipher.</summary>
        public virtual void Dispose()
        {
            if (Key != null) Array.Clear(Key, 0, Key.Length);
            if (Nonce != null) Array.Clear(Nonce, 0, Nonce.Length);
            GC.SuppressFinalize(this);
        }
    }
}