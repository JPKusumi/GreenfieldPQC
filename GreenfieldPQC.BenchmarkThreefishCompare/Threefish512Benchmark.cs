using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using GreenfieldPQC.Cryptography; // for SymmetricCipher and Threefish512 base

namespace GreenfieldPQC.BenchmarkThreefishCompare
{
    /// <summary>
    /// Benchmark-only wrapper for Threefish-512 that implements missing SymmetricCipher members.
    /// </summary>
    public class Threefish512Benchmark : ThreefishBenchmarkCore
    {
        public Threefish512Benchmark(byte[] key, byte[] tweakBytes)
            : base(key, tweakBytes)
        {
        }

        public override string AlgorithmName => "Threefish-512";

        // Sync in-place encryption (core method needed for benchmark)
        public override void EncryptInPlace(Span<byte> inputOutput)
        {
            if (inputOutput.IsEmpty) return;
            counter = 0;
            RunCipherInPlace(inputOutput);
        }

        // Decrypt is symmetric in CTR mode
        public override void DecryptInPlace(Span<byte> inputOutput)
        {
            EncryptInPlace(inputOutput);
        }

        // Byte array wrappers (minimal stubs)
        public override byte[] Encrypt(byte[] plaintext)
        {
            var result = (byte[])plaintext.Clone();
            EncryptInPlace(result.AsSpan());
            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            return Encrypt(ciphertext); // CTR symmetry
        }

        // Stream methods (minimal sync/async stubs)
        public override void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            EncryptStreamSync(input, output, bufferSize, nonceGenerator);
        }

        public override void EncryptStreamSync(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            byte[] buffer = new byte[bufferSize];
            long bytesProcessed = 0;
            counter = 0;

            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, bufferSize)) > 0)
            {
                if (nonceGenerator != null && (bytesProcessed / (1024 * 1024)) != ((bytesProcessed + bytesRead) / (1024 * 1024)))
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                Span<byte> span = buffer.AsSpan(0, bytesRead);
                EncryptInPlace(span);
                output.Write(buffer, 0, bytesRead);
                bytesProcessed += bytesRead;
            }
        }

        public override Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            // Minimal async wrapper around sync
            EncryptStreamSync(input, output, bufferSize, nonceGenerator != null ? l => nonceGenerator(l).GetAwaiter().GetResult() : null);
            return Task.CompletedTask;
        }

        // Decrypt stream symmetric
        public override void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            EncryptStream(input, output, bufferSize, nonceGenerator);
        }

        public override Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            return EncryptStreamAsync(input, output, bufferSize, progress, segmentProgress, nonceGenerator, cancellationToken);
        }

        // Other required members (if any remain, add stubs)
        protected override void UpdateNonce(byte[] newNonce)
        {
            base.UpdateNonce(newNonce);
            // Your existing tweak/counter reset is already in base
        }
    }
}