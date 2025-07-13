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
        private readonly byte[] data; // Test data
        private readonly ISymmetricCipher kusumi512;
        private readonly string logPath;

        public CipherBenchmarks()
        {
            logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cipher_benchmarks_log.txt");
            try
            {
                // Initialize random keys, nonces, and data
                data = new byte[1024 * 1024]; // 1 MB test data
                RandomNumberGenerator.Fill(data);
                try
                {
                    kusumi512 = CryptoFactory.CreateKusumi512(CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512), CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512));
                    Console.WriteLine("Kusumi512 initialized successfully.");
                    File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Kusumi512 initialized successfully.\n");
                }
                catch (Exception ex)
                {
                    File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Kusumi512 initialization failed: {ex.Message}\n");
                    throw;
                }
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - CipherBenchmarks initialized: Kusumi512\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Cipher initialization failed: {ex.Message}");
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - CipherBenchmarks initialization failed: {ex.Message}\n");
                throw;
            }
        }

        [Params(1024, 1024 * 1024)] // Test 1 KB and 1 MB
        public int DataSize { get; set; }

        [Benchmark]
        public void Kusumi512_Encrypt()
        {
            try
            {
                var input = data.AsSpan(0, DataSize).ToArray();
                kusumi512.EncryptSync(input);
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Kusumi512_Encrypt failed: {ex.Message}\n");
                throw;
            }
        }

        [Benchmark]
        public void Kusumi512_EncryptInPlace()
        {
            try
            {
                var buffer = data.AsSpan(0, DataSize).ToArray();
                kusumi512.EncryptInPlaceSync(buffer.AsSpan());
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Kusumi512_EncryptInPlace failed: {ex.Message}\n");
                throw;
            }
        }

        [Benchmark]
        public void Kusumi512_EncryptStream()
        {
            try
            {
                using var input = new MemoryStream(data, 0, DataSize);
                using var output = new MemoryStream();
                kusumi512.EncryptStreamSync(input, output, 4096);
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - Kusumi512_EncryptStream failed: {ex.Message}\n");
                throw;
            }
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - CipherBenchmarks completed. Check BenchmarkDotNet.Artifacts for detailed results.\n");
        }
    }
}