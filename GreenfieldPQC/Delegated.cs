using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Numerics;

namespace GreenfieldPQC.Cryptography
{
    /// <summary>
    /// Kusumi512-Poly1305 AEAD cipher, with 512-bit key, 96-bit nonce, 100-byte block size, and 128-bit tag.
    /// Always use a unique nonce for each encryption operation to prevent nonce-reuse attacks.
    /// </summary>
    public sealed class Kusumi512Poly1305 : SymmetricCipher
    {
        private const int TagLength = 16; // 128-bit tag for Poly1305
        private readonly Kusumi512 _kusumi512;

        public override string AlgorithmName => "Kusumi512-Poly1305";

        public Kusumi512Poly1305(byte[] key, byte[] nonce) : base(key, nonce)
        {
            if (key.Length != 64) throw new ArgumentException("Key must be 512 bits (64 bytes).", nameof(key));
            if (nonce.Length != 12) throw new ArgumentException("Nonce for Kusumi512-Poly1305 must be 96 bits (12 bytes).", nameof(nonce));
            _kusumi512 = new Kusumi512(key, nonce);
        }

        public override async Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            byte[] ciphertext = _kusumi512.RunCipher(plaintext, startCounter: 1);
            byte[] poly1305Key = _kusumi512.GeneratePoly1305Key();
            byte[] tag = Poly1305.ComputeTag(poly1305Key, ciphertext);
            byte[] result = new byte[ciphertext.Length + TagLength];
            Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, ciphertext.Length, TagLength);
            return await Task.FromResult(result).ConfigureAwait(false);
        }

        public override byte[] Encrypt(byte[] plaintext)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            byte[] ciphertext = _kusumi512.RunCipher(plaintext, startCounter: 1);
            byte[] poly1305Key = _kusumi512.GeneratePoly1305Key();
            byte[] tag = Poly1305.ComputeTag(poly1305Key, ciphertext);
            byte[] result = new byte[ciphertext.Length + TagLength];
            Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, ciphertext.Length, TagLength);
            return result;
        }

        public override async Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (ciphertext.Length < TagLength)
                throw new ArgumentException("Ciphertext is too short to contain a valid Poly1305 tag.");
            byte[] tag = new byte[TagLength];
            byte[] actualCiphertext = new byte[ciphertext.Length - TagLength];
            Buffer.BlockCopy(ciphertext, ciphertext.Length - TagLength, tag, 0, TagLength);
            Buffer.BlockCopy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);
            byte[] poly1305Key = _kusumi512.GeneratePoly1305Key();
            byte[] computedTag = Poly1305.ComputeTag(poly1305Key, actualCiphertext);
            if (!CryptographicOperations.FixedTimeEquals(tag, computedTag))
                throw new CryptographicException("Poly1305 tag verification failed.");
            return await Task.FromResult(_kusumi512.RunCipher(actualCiphertext, startCounter: 1)).ConfigureAwait(false);
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (ciphertext.Length < TagLength)
                throw new ArgumentException("Ciphertext is too short to contain a valid Poly1305 tag.");
            byte[] tag = new byte[TagLength];
            byte[] actualCiphertext = new byte[ciphertext.Length - TagLength];
            Buffer.BlockCopy(ciphertext, ciphertext.Length - TagLength, tag, 0, TagLength);
            Buffer.BlockCopy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);
            byte[] poly1305Key = _kusumi512.GeneratePoly1305Key();
            byte[] computedTag = Poly1305.ComputeTag(poly1305Key, actualCiphertext);
            if (!CryptographicOperations.FixedTimeEquals(tag, computedTag))
                throw new CryptographicException("Poly1305 tag verification failed.");
            return _kusumi512.RunCipher(actualCiphertext, startCounter: 1);
        }

        public override Task EncryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException("Kusumi512-Poly1305 does not support in-place transformation.");
        }

        public override void EncryptInPlace(Span<byte> inputOutput)
        {
            throw new NotSupportedException("Kusumi512-Poly1305 does not support in-place transformation.");
        }

        public override Task DecryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException("Kusumi512-Poly1305 does not support in-place transformation.");
        }

        public override void DecryptInPlace(Span<byte> inputOutput)
        {
            throw new NotSupportedException("Kusumi512-Poly1305 does not support in-place transformation.");
        }

        public override async Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            long bytesPerSegment = 1024 * 1024; // 1 MB segments
            long bytesProcessed = 0;
            int segmentCount = 0;
            byte[] segmentBuffer = new byte[bytesPerSegment];
            int bytesInBuffer = 0;

            byte[] buffer = new byte[bufferSize];
            while (true)
            {
                int bytesRead = await input.ReadAsync(buffer, 0, bufferSize, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                int offset = 0;
                while (offset < bytesRead)
                {
                    int bytesToCopy = Math.Min(bytesRead - offset, (int)(bytesPerSegment - bytesInBuffer));
                    Buffer.BlockCopy(buffer, offset, segmentBuffer, bytesInBuffer, bytesToCopy);
                    bytesInBuffer += bytesToCopy;
                    offset += bytesToCopy;
                    bytesProcessed += bytesToCopy;

                    if (bytesInBuffer == bytesPerSegment)
                    {
                        if (nonceGenerator != null)
                        {
                            UpdateNonce(await nonceGenerator(bytesProcessed).ConfigureAwait(false));
                            segmentProgress?.Report(++segmentCount);
                        }
                        byte[] ciphertext = await EncryptAsync(segmentBuffer, cancellationToken).ConfigureAwait(false);
                        await output.WriteAsync(ciphertext, 0, ciphertext.Length, cancellationToken).ConfigureAwait(false);
                        bytesInBuffer = 0;
                    }
                }
            }

            if (bytesInBuffer > 0)
            {
                byte[] finalSegment = new byte[bytesInBuffer];
                Buffer.BlockCopy(segmentBuffer, 0, finalSegment, 0, bytesInBuffer);
                if (nonceGenerator != null)
                {
                    UpdateNonce(await nonceGenerator(bytesProcessed).ConfigureAwait(false));
                    segmentProgress?.Report(++segmentCount);
                }
                byte[] ciphertext = await EncryptAsync(finalSegment, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(ciphertext, 0, ciphertext.Length, cancellationToken).ConfigureAwait(false);
            }
        }

        public override void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            long bytesPerSegment = 1024 * 1024; // 1 MB segments
            long bytesProcessed = 0;
            byte[] segmentBuffer = new byte[bytesPerSegment];
            int bytesInBuffer = 0;

            byte[] buffer = new byte[bufferSize];
            while (input.Read(buffer, 0, bufferSize) is int bytesRead && bytesRead > 0)
            {
                int offset = 0;
                while (offset < bytesRead)
                {
                    int bytesToCopy = Math.Min(bytesRead - offset, (int)(bytesPerSegment - bytesInBuffer));
                    Buffer.BlockCopy(buffer, offset, segmentBuffer, bytesInBuffer, bytesToCopy);
                    bytesInBuffer += bytesToCopy;
                    offset += bytesToCopy;
                    bytesProcessed += bytesToCopy;

                    if (bytesInBuffer == bytesPerSegment)
                    {
                        if (nonceGenerator != null)
                        {
                            UpdateNonce(nonceGenerator(bytesProcessed));
                        }
                        byte[] ciphertext = Encrypt(segmentBuffer);
                        output.Write(ciphertext, 0, ciphertext.Length);
                        bytesInBuffer = 0;
                    }
                }
            }

            if (bytesInBuffer > 0)
            {
                byte[] finalSegment = new byte[bytesInBuffer];
                Buffer.BlockCopy(segmentBuffer, 0, finalSegment, 0, bytesInBuffer);
                if (nonceGenerator != null)
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                byte[] ciphertext = Encrypt(finalSegment);
                output.Write(ciphertext, 0, ciphertext.Length);
            }
        }

        public override async Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            long bytesPerSegment = 1024 * 1024; // 1 MB segments
            long bytesProcessed = 0;
            int segmentCount = 0;
            byte[] segmentBuffer = new byte[bytesPerSegment + TagLength];
            int bytesInBuffer = 0;

            byte[] buffer = new byte[bufferSize];
            while (true)
            {
                int bytesRead = await input.ReadAsync(buffer, 0, bufferSize, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                int offset = 0;
                while (offset < bytesRead)
                {
                    int bytesToCopy = Math.Min(bytesRead - offset, (int)(bytesPerSegment + TagLength - bytesInBuffer));
                    Buffer.BlockCopy(buffer, offset, segmentBuffer, bytesInBuffer, bytesToCopy);
                    bytesInBuffer += bytesToCopy;
                    offset += bytesToCopy;
                    bytesProcessed += bytesToCopy;

                    if (bytesInBuffer >= bytesPerSegment + TagLength)
                    {
                        if (nonceGenerator != null)
                        {
                            UpdateNonce(await nonceGenerator(bytesProcessed - bytesInBuffer).ConfigureAwait(false));
                            segmentProgress?.Report(++segmentCount);
                        }
                        byte[] segment = new byte[bytesPerSegment + TagLength];
                        Array.Copy(segmentBuffer, 0, segment, 0, bytesPerSegment + TagLength);
                        byte[] plaintext = await DecryptAsync(segment, cancellationToken).ConfigureAwait(false);
                        await output.WriteAsync(plaintext, 0, plaintext.Length, cancellationToken).ConfigureAwait(false);
                        bytesInBuffer = 0;
                    }
                }
            }

            if (bytesInBuffer > 0)
            {
                if (bytesInBuffer < TagLength)
                    throw new CryptographicException("Incomplete segment: insufficient data for Poly1305 tag.");
                byte[] finalSegment = new byte[bytesInBuffer];
                Array.Copy(segmentBuffer, 0, finalSegment, 0, bytesInBuffer);
                if (nonceGenerator != null)
                {
                    UpdateNonce(await nonceGenerator(bytesProcessed - bytesInBuffer).ConfigureAwait(false));
                    segmentProgress?.Report(++segmentCount);
                }
                byte[] plaintext = await DecryptAsync(finalSegment, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(plaintext, 0, plaintext.Length, cancellationToken).ConfigureAwait(false);
            }
        }

        public override void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            long bytesPerSegment = 1024 * 1024; // 1 MB segments
            long bytesProcessed = 0;
            byte[] segmentBuffer = new byte[bytesPerSegment + TagLength];
            int bytesInBuffer = 0;

            byte[] buffer = new byte[bufferSize];
            while (input.Read(buffer, 0, bufferSize) is int bytesRead && bytesRead > 0)
            {
                int offset = 0;
                while (offset < bytesRead)
                {
                    int bytesToCopy = Math.Min(bytesRead - offset, (int)(bytesPerSegment + TagLength - bytesInBuffer));
                    Buffer.BlockCopy(buffer, offset, segmentBuffer, bytesInBuffer, bytesToCopy);
                    bytesInBuffer += bytesToCopy;
                    offset += bytesToCopy;
                    bytesProcessed += bytesToCopy;

                    if (bytesInBuffer >= bytesPerSegment + TagLength)
                    {
                        if (nonceGenerator != null)
                        {
                            UpdateNonce(nonceGenerator(bytesProcessed - bytesInBuffer));
                        }
                        byte[] segment = new byte[bytesPerSegment + TagLength];
                        Array.Copy(segmentBuffer, 0, segment, 0, bytesPerSegment + TagLength);
                        byte[] plaintext = Decrypt(segment);
                        output.Write(plaintext, 0, plaintext.Length);
                        bytesInBuffer = 0;
                    }
                }
            }

            if (bytesInBuffer > 0)
            {
                if (bytesInBuffer < TagLength)
                    throw new CryptographicException("Incomplete segment: insufficient data for Poly1305 tag.");
                byte[] finalSegment = new byte[bytesInBuffer];
                Array.Copy(segmentBuffer, 0, finalSegment, 0, bytesInBuffer);
                if (nonceGenerator != null)
                {
                    UpdateNonce(nonceGenerator(bytesProcessed - bytesInBuffer));
                }
                byte[] plaintext = Decrypt(finalSegment);
                output.Write(plaintext, 0, plaintext.Length);
            }
        }

        protected override void UpdateNonce(byte[] newNonce)
        {
            if (newNonce == null) throw new ArgumentNullException(nameof(newNonce));
            if (newNonce.Length != 12) throw new ArgumentException("Nonce for Kusumi512-Poly1305 must be 96 bits (12 bytes).", nameof(newNonce));
            base.UpdateNonce(newNonce);
            _kusumi512.SetNonce(newNonce);
        }
    }

    /// <summary>
    /// Internal Poly1305 implementation for computing 128-bit authentication tags.
    /// </summary>
    internal static class Poly1305
    {
        private static readonly BigInteger P = BigInteger.Pow(2, 130) - 5; // 2^130 - 5
        private const int BlockSize = 16; // 128-bit blocks

        public static byte[] ComputeTag(byte[] key, byte[] message)
        {
            if (key == null || key.Length != 32) throw new ArgumentException("Key must be 256 bits (32 bytes).", nameof(key));
            if (message == null) throw new ArgumentNullException(nameof(message));

            byte[] rBytes = new byte[16];
            Array.Copy(key, 0, rBytes, 0, 16);
            rBytes[3] &= 0x0F; rBytes[4] &= 0xFC; rBytes[7] &= 0x0F; rBytes[8] &= 0xFC;
            rBytes[11] &= 0x0F; rBytes[12] &= 0xFC; rBytes[15] &= 0x0F;
            BigInteger r = new BigInteger(rBytes, isUnsigned: true, isBigEndian: false);
            byte[] sBytes = new byte[16];
            Array.Copy(key, 16, sBytes, 0, 16);
            BigInteger s = new BigInteger(sBytes, isUnsigned: true, isBigEndian: false);

            BigInteger a = 0; // Accumulator
            byte[] block = new byte[17]; // 128-bit block + 0x01 byte
            int bytesProcessed = 0;

            while (bytesProcessed < message.Length)
            {
                int bytesToProcess = Math.Min(BlockSize, message.Length - bytesProcessed);
                Array.Copy(message, bytesProcessed, block, 0, bytesToProcess);
                block[bytesToProcess] = 0x01; // Add 2^(8*blocksize) bit
                for (int i = bytesToProcess + 1; i < 17; i++)
                    block[i] = 0;

                BigInteger m = new BigInteger(block, isUnsigned: true, isBigEndian: false);
                a = (a + m) * r % P;
                bytesProcessed += BlockSize;
            }

            a = (a + s) % P;
            byte[] tag = a.ToByteArray(isUnsigned: true, isBigEndian: false);
            if (tag.Length > 16)
            {
                byte[] result = new byte[16];
                Array.Copy(tag, 0, result, 0, 16);
                tag = result;
            }
            else if (tag.Length < 16)
            {
                byte[] paddedTag = new byte[16];
                Array.Copy(tag, 0, paddedTag, 0, tag.Length);
                tag = paddedTag;
            }
            return tag;
        }
    }
}