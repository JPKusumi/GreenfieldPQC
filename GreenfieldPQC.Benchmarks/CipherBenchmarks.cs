using BenchmarkDotNet.Attributes;
using GreenfieldPQC.Cryptography;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using static GreenfieldPQC.Cryptography.CryptoFactory;

namespace GreenfieldPQC.Benchmarks
{
    [MemoryDiagnoser] // Tracks memory allocation
    [RPlotExporter] // Exports plots
    public class CipherBenchmarks
    {
        private byte[] _key;
        private byte[] _nonce;
        private byte[] _originalData1KB;
        private byte[] _originalData1MB;
        private byte[] _buffer1KB;
        private byte[] _buffer1MB;
        private ISymmetricCipher _kusumi512;
        private string logPath;

        [GlobalSetup]
        public void GlobalSetup()
        {
            logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cipher_benchmarks_log.txt");
            // Initialize once
            _key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            _nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            _kusumi512 = CryptoFactory.CreateKusumi512(_key, _nonce);

            // Pre-allocate data and buffers
            _originalData1KB = new byte[1024];
            _originalData1MB = new byte[1024 * 1024];
            RandomNumberGenerator.Fill(_originalData1KB);
            RandomNumberGenerator.Fill(_originalData1MB);

            _buffer1KB = new byte[1024];
            _buffer1MB = new byte[1024 * 1024];

            File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - GlobalSetup completed.\n");
        }

        [IterationSetup]
        public void IterationSetup()
        {
            // Reset buffers per iteration to avoid state carryover (minimal allocation, but necessary for correctness)
            Array.Copy(_originalData1KB, _buffer1KB, 1024);
            Array.Copy(_originalData1MB, _buffer1MB, 1024 * 1024);
        }

        [Params(1024, 1024 * 1024)] // Test 1 KB and 1 MB
        public int DataSize { get; set; }

        private Span<byte> GetBuffer()
        {
            return DataSize == 1024 ? _buffer1KB.AsSpan() : _buffer1MB.AsSpan();
        }

        [Benchmark]
        public byte[] Kusumi512_Encrypt()
        {
            // Allocates new output array (expected)
            var input = GetBuffer().ToArray();  // Copy to simulate "new input" (allocation measured)
            return _kusumi512.Encrypt(input);
        }

        [Benchmark]
        public void Kusumi512_EncryptInPlace()
        {
            // No new allocation for data (operates on pre-allocated buffer)
            _kusumi512.EncryptInPlace(GetBuffer());
        }

        [Benchmark]
        public void Kusumi512_EncryptStream()
        {
            // Stream allocations (buffers inside MemoryStream)
            using var input = new MemoryStream(GetBuffer().ToArray());  // Copy for stream (allocation measured)
            using var output = new MemoryStream();
            _kusumi512.EncryptStream(input, output, 4096);
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - CipherBenchmarks completed. Check BenchmarkDotNet.Artifacts for detailed results.\n");
        }
    }
}