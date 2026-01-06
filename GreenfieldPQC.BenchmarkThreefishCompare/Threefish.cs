using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace GreenfieldPQC.Cryptography
{
    /// <summary>
    /// Threefish-512 block cipher in CTR mode, with 512-bit key, 128-bit tweak, 512-bit block size, and 64-bit counter.
    /// </summary>
    public class Threefish512 : SymmetricCipher
    {
        public override string AlgorithmName => "Threefish512";

        private const int BlockSizeBytes = 64;
        private const int BlockSizeWords = 8;
        private const int TweakSizeWords = 3; // t0, t1, t2 = t0 ^ t1
        private const int KeySizeWords = BlockSizeWords + 1; // k0..k7, k8 = parity
        private const int Rounds = 72;
        private const ulong C240 = 0x1BD11BDAA9FC1A22UL;

        private readonly ulong[] keySchedule = new ulong[KeySizeWords];
        private readonly ulong[] tweak = new ulong[TweakSizeWords];
        private ulong counter;

        private readonly byte[] keystreamBuffer = new byte[BlockSizeBytes];

        private static readonly int[,] Rotations = new int[8, 4] {
            { 46, 36, 19, 37 },
            { 33, 27, 14, 42 },
            { 17, 49, 36, 39 },
            { 44, 9, 54, 56 },
            { 39, 30, 34, 24 },
            { 13, 50, 10, 17 },
            { 25, 29, 39, 43 },
            { 8, 35, 56, 22 }
        };

        private static readonly int[] PermuteTable = { 0, 3, 6, 1, 4, 7, 2, 5 };

        public Threefish512(byte[] key, byte[] tweakBytes) : base(key, tweakBytes)
        {
            if (key.Length != 64) throw new ArgumentException("Key must be 512 bits (64 bytes).", nameof(key));
            if (tweakBytes.Length != 16) throw new ArgumentException("Tweak must be 128 bits (16 bytes).", nameof(tweakBytes));

            // Load key into ulong array (little-endian)
            for (int i = 0; i < BlockSizeWords; i++)
            {
                keySchedule[i] = BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(i * 8));
            }
            ulong parity = C240;
            for (int i = 0; i < BlockSizeWords; i++)
            {
                parity ^= keySchedule[i];
            }
            keySchedule[BlockSizeWords] = parity;

            // Load tweak
            this.tweak[0] = BinaryPrimitives.ReadUInt64LittleEndian(tweakBytes.AsSpan(0));
            this.tweak[1] = BinaryPrimitives.ReadUInt64LittleEndian(tweakBytes.AsSpan(8));
            this.tweak[2] = this.tweak[0] ^ this.tweak[1];

            counter = 0;
        }

        public override async Task<byte[]> Encrypt(byte[] plaintext, CancellationToken cancellationToken = default)
        {
            counter = 0;
            return await Task.FromResult(RunCipher(plaintext)).ConfigureAwait(false);
        }

        public override byte[] EncryptSync(byte[] plaintext)
        {
            counter = 0;
            return RunCipher(plaintext);
        }

        public override async Task<byte[]> Decrypt(byte[] ciphertext, CancellationToken cancellationToken = default)
        {
            counter = 0;
            return await Task.FromResult(RunCipher(ciphertext)).ConfigureAwait(false);
        }

        public override byte[] DecryptSync(byte[] ciphertext)
        {
            counter = 0;
            return RunCipher(ciphertext);
        }

        public override async Task EncryptInPlace(Memory<byte> inputOutput, CancellationToken cancellationToken = default)
        {
            EncryptInPlaceSync(inputOutput.Span);
            await Task.CompletedTask.ConfigureAwait(false);
        }

        public override void EncryptInPlaceSync(Span<byte> inputOutput)
        {
            if (inputOutput.Length == 0) throw new ArgumentNullException(nameof(inputOutput));
            counter = 0;
            RunCipherInPlace(inputOutput);
        }

        public override async Task DecryptInPlace(Memory<byte> inputOutput, CancellationToken cancellationToken = default)
        {
            DecryptInPlaceSync(inputOutput.Span);
            await Task.CompletedTask.ConfigureAwait(false);
        }

        public override void DecryptInPlaceSync(Span<byte> inputOutput)
        {
            if (inputOutput.Length == 0) throw new ArgumentNullException(nameof(inputOutput));
            counter = 0;
            RunCipherInPlace(inputOutput);
        }

        public override async Task EncryptStream(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>?> nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long totalBytes = input.CanSeek ? input.Length : -1;
            long bytesProcessed = 0;
            int segmentCount = 0;
            long bytesPerSegment = 1024 * 1024;
            counter = 0;

            int bytesRead;
            while ((bytesRead = await input.ReadAsync(buffer, 0, bufferSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (nonceGenerator != null && (bytesProcessed / bytesPerSegment) != ((bytesProcessed + bytesRead - 1) / bytesPerSegment))
                {
                    UpdateNonce(await nonceGenerator(bytesProcessed).ConfigureAwait(false));
                    segmentProgress?.Report(++segmentCount);
                }
                Span<byte> span = buffer.AsSpan(0, bytesRead);
                EncryptInPlaceSync(span);
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                bytesProcessed += bytesRead;
                if (totalBytes > 0)
                    progress?.Report((double)bytesProcessed / totalBytes);
            }
        }

        public override void EncryptStreamSync(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long bytesProcessed = 0;
            long bytesPerSegment = 1024 * 1024;
            counter = 0;

            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, bufferSize)) > 0)
            {
                if (nonceGenerator != null && (bytesProcessed / bytesPerSegment) != ((bytesProcessed + bytesRead - 1) / bytesPerSegment))
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                Span<byte> span = buffer.AsSpan(0, bytesRead);
                EncryptInPlaceSync(span);
                output.Write(buffer, 0, bytesRead);
                bytesProcessed += bytesRead;
            }
        }

        public override async Task DecryptStream(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            await EncryptStream(input, output, bufferSize, progress, segmentProgress, nonceGenerator, cancellationToken); // CTR is symmetric
        }

        public override void DecryptStreamSync(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            EncryptStreamSync(input, output, bufferSize, nonceGenerator); // CTR is symmetric
        }

        private byte[] RunCipher(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            byte[] result = new byte[data.Length];
            data.CopyTo(result, 0);
            RunCipherInPlace(result.AsSpan());
            return result;
        }

        private void RunCipherInPlace(Span<byte> data)
        {
            int size = data.Length;
            int numBlocks = (size + BlockSizeBytes - 1) / BlockSizeBytes;
            if (counter + (ulong)numBlocks < counter) throw new CryptographicException("Counter would overflow.");

            for (int i = 0; i < numBlocks; i++)
            {
                GenerateKeystream(counter + (ulong)i, keystreamBuffer);
                int offset = i * BlockSizeBytes;
                int blockLength = Math.Min(BlockSizeBytes, size - offset);
                for (int j = 0; j < blockLength; j++)
                {
                    data[offset + j] ^= keystreamBuffer[j];
                }
            }
            counter += (ulong)numBlocks;
        }

        private void GenerateKeystream(ulong ctr, byte[] output)
        {
            ulong[] block = new ulong[BlockSizeWords];
            block[0] = ctr;
            // Other positions 0
            EncryptBlock(block);
            for (int i = 0; i < BlockSizeWords; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(i * 8), block[i]);
            }
        }

        private void EncryptBlock(ulong[] block)
        {
            ulong v0 = block[0], v1 = block[1], v2 = block[2], v3 = block[3],
                  v4 = block[4], v5 = block[5], v6 = block[6], v7 = block[7];

            for (int d = 0; d < Rounds; d += 4)
            {
                v0 += keySchedule[d % KeySizeWords];
                v1 += keySchedule[(d + 1) % KeySizeWords];
                v2 += keySchedule[(d + 2) % KeySizeWords];
                v3 += keySchedule[(d + 3) % KeySizeWords];
                v4 += keySchedule[(d + 4) % KeySizeWords];
                v5 += keySchedule[(d + 5) % KeySizeWords] + tweak[d % TweakSizeWords];
                v6 += keySchedule[(d + 6) % KeySizeWords] + tweak[(d + 1) % TweakSizeWords];
                v7 += keySchedule[(d + 7) % KeySizeWords] + (ulong)(d / 4);

                Mix(ref v0, ref v1, Rotations[d % 8, 0]);
                Mix(ref v2, ref v3, Rotations[d % 8, 1]);
                Mix(ref v4, ref v5, Rotations[d % 8, 2]);
                Mix(ref v6, ref v7, Rotations[d % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

                Mix(ref v0, ref v1, Rotations[(d + 1) % 8, 0]);
                Mix(ref v2, ref v3, Rotations[(d + 1) % 8, 1]);
                Mix(ref v4, ref v5, Rotations[(d + 1) % 8, 2]);
                Mix(ref v6, ref v7, Rotations[(d + 1) % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

                Mix(ref v0, ref v1, Rotations[(d + 2) % 8, 0]);
                Mix(ref v2, ref v3, Rotations[(d + 2) % 8, 1]);
                Mix(ref v4, ref v5, Rotations[(d + 2) % 8, 2]);
                Mix(ref v6, ref v7, Rotations[(d + 2) % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

                Mix(ref v0, ref v1, Rotations[(d + 3) % 8, 0]);
                Mix(ref v2, ref v3, Rotations[(d + 3) % 8, 1]);
                Mix(ref v4, ref v5, Rotations[(d + 3) % 8, 2]);
                Mix(ref v6, ref v7, Rotations[(d + 3) % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
            }

            v0 += keySchedule[Rounds % KeySizeWords];
            v1 += keySchedule[(Rounds + 1) % KeySizeWords];
            v2 += keySchedule[(Rounds + 2) % KeySizeWords];
            v3 += keySchedule[(Rounds + 3) % KeySizeWords];
            v4 += keySchedule[(Rounds + 4) % KeySizeWords];
            v5 += keySchedule[(Rounds + 5) % KeySizeWords] + tweak[Rounds % TweakSizeWords];
            v6 += keySchedule[(Rounds + 6) % KeySizeWords] + tweak[(Rounds + 1) % TweakSizeWords];
            v7 += keySchedule[(Rounds + 7) % KeySizeWords] + (ulong)(Rounds / 4);

            block[0] = v0;
            block[1] = v1;
            block[2] = v2;
            block[3] = v3;
            block[4] = v4;
            block[5] = v5;
            block[6] = v6;
            block[7] = v7;
        }

        private static void Mix(ref ulong x, ref ulong y, int r)
        {
            x += y;
            y = RotateLeft(y ^ x, r);
        }

        private static ulong RotateLeft(ulong x, int n)
        {
            return (x << n) | (x >> (64 - n));
        }

        private static void Permute(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3, ref ulong v4, ref ulong v5, ref ulong v6, ref ulong v7)
        {
            ulong temp0 = v0, temp1 = v1, temp2 = v2, temp3 = v3, temp4 = v4, temp5 = v5, temp6 = v6, temp7 = v7;
            v0 = temp0;
            v1 = temp3;
            v2 = temp6;
            v3 = temp1;
            v4 = temp4;
            v5 = temp7;
            v6 = temp2;
            v7 = temp5;
        }

        protected override void UpdateNonce(byte[] newNonce)
        {
            if (newNonce == null) throw new ArgumentNullException(nameof(newNonce));
            if (newNonce.Length != 16) throw new ArgumentException("Tweak must be 128 bits (16 bytes).", nameof(newNonce));
            base.UpdateNonce(newNonce);
            this.tweak[0] = BinaryPrimitives.ReadUInt64LittleEndian(newNonce.AsSpan(0));
            this.tweak[1] = BinaryPrimitives.ReadUInt64LittleEndian(newNonce.AsSpan(8));
            this.tweak[2] = this.tweak[0] ^ this.tweak[1];
            counter = 0;
        }
    }
}