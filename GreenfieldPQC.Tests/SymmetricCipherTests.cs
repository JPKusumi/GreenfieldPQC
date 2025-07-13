using GreenfieldPQC.Cryptography;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;
using static GreenfieldPQC.Cryptography.CryptoFactory;

namespace GreenfieldPQC.Tests
{
    public class SymmetricCipherTests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "symmetric_cipher_test_log.txt");

        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }

        [Fact]
        public void CreateKusumi512_ValidParameters_CreatesCipher()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);

            Assert.NotNull(cipher);
            Assert.Equal("Kusumi512", cipher.AlgorithmName);
            Log("CreateKusumi512_ValidParameters_CreatesCipher passed");
        }

        [Fact]
        public void CreateKusumi512Poly1305_ValidParameters_CreatesCipher()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);
            using var cipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);

            Assert.NotNull(cipher);
            Assert.Equal("Kusumi512-Poly1305", cipher.AlgorithmName);
            Log("CreateKusumi512Poly1305_ValidParameters_CreatesCipher passed");
        }

        [Fact]
        public async Task Kusumi512_EncryptDecrypt_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            byte[] ciphertext = await cipher.Encrypt(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce); // Reset counter
            byte[] decrypted = await decryptCipher.Decrypt(ciphertext);

            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Assert.NotSame(plaintext, ciphertext);
            Log($"Kusumi512_EncryptDecrypt_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertext.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public void Kusumi512_EncryptDecryptSync_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            byte[] ciphertext = cipher.EncryptSync(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce); // Reset counter
            byte[] decrypted = decryptCipher.DecryptSync(ciphertext);

            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Assert.NotSame(plaintext, ciphertext);
            Log($"Kusumi512_EncryptDecryptSync_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertext.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public async Task Kusumi512Poly1305_EncryptDecrypt_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);
            using var cipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            byte[] ciphertext = await cipher.Encrypt(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce); // Reset counter
            byte[] decrypted = await decryptCipher.Decrypt(ciphertext);

            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Assert.NotSame(plaintext, ciphertext);
            Log($"Kusumi512Poly1305_EncryptDecrypt_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertext.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public void Kusumi512Poly1305_EncryptDecryptSync_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);
            using var cipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            byte[] ciphertext = cipher.EncryptSync(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce); // Reset counter
            byte[] decrypted = decryptCipher.DecryptSync(ciphertext);

            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Assert.NotSame(plaintext, ciphertext);
            Log($"Kusumi512Poly1305_EncryptDecryptSync_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertext.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public async Task Kusumi512_EncryptStream_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var encryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            using var input = new MemoryStream(plaintext);
            using var ciphertextStream = new MemoryStream();
            using var decryptedStream = new MemoryStream();
            await encryptCipher.EncryptStream(input, ciphertextStream, 1024);
            ciphertextStream.Position = 0;
            await decryptCipher.DecryptStream(ciphertextStream, decryptedStream, 1024);

            byte[] decrypted = decryptedStream.ToArray();
            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Log($"Kusumi512_EncryptStream_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertextStream.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public void Kusumi512_EncryptStreamSync_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var encryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            using var input = new MemoryStream(plaintext);
            using var ciphertextStream = new MemoryStream();
            using var decryptedStream = new MemoryStream();
            encryptCipher.EncryptStreamSync(input, ciphertextStream, 1024);
            ciphertextStream.Position = 0;
            decryptCipher.DecryptStreamSync(ciphertextStream, decryptedStream, 1024);

            byte[] decrypted = decryptedStream.ToArray();
            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Log($"Kusumi512_EncryptStreamSync_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertextStream.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public async Task Kusumi512Poly1305_EncryptStream_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);
            using var encryptCipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
            using var decryptCipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            using var input = new MemoryStream(plaintext);
            using var ciphertextStream = new MemoryStream();
            using var decryptedStream = new MemoryStream();
            await encryptCipher.EncryptStream(input, ciphertextStream, 1024);
            ciphertextStream.Position = 0;
            await decryptCipher.DecryptStream(ciphertextStream, decryptedStream, 1024);

            byte[] decrypted = decryptedStream.ToArray();
            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Log($"Kusumi512Poly1305_EncryptStream_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertextStream.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public void Kusumi512Poly1305_EncryptStreamSync_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);
            using var encryptCipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
            using var decryptCipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
            byte[] plaintext = new byte[4096];
            RandomNumberGenerator.Fill(plaintext);

            using var input = new MemoryStream(plaintext);
            using var ciphertextStream = new MemoryStream();
            using var decryptedStream = new MemoryStream();
            encryptCipher.EncryptStreamSync(input, ciphertextStream, 1024);
            ciphertextStream.Position = 0;
            decryptCipher.DecryptStreamSync(ciphertextStream, decryptedStream, 1024);

            byte[] decrypted = decryptedStream.ToArray();
            Assert.Equal(plaintext.Length, decrypted.Length);
            Assert.Equal(plaintext, decrypted);
            Log($"Kusumi512Poly1305_EncryptStreamSync_RoundTrip passed: plaintext length={plaintext.Length}, ciphertext length={ciphertextStream.Length}, decrypted length={decrypted.Length}");
        }

        [Fact]
        public async Task Kusumi512_EncryptInPlace_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var encryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] data = new byte[4096];
            RandomNumberGenerator.Fill(data);
            byte[] original = data.ToArray();

            await encryptCipher.EncryptInPlace(data.AsMemory());
            await decryptCipher.DecryptInPlace(data.AsMemory());

            Assert.Equal(original.Length, data.Length);
            Assert.Equal(original, data);
            Log($"Kusumi512_EncryptInPlace_RoundTrip passed: original length={original.Length}, data length={data.Length}");
        }

        [Fact]
        public void Kusumi512_EncryptInPlaceSync_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var encryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] data = new byte[4096];
            RandomNumberGenerator.Fill(data);
            byte[] original = data.ToArray();

            encryptCipher.EncryptInPlaceSync(data.AsSpan());
            decryptCipher.DecryptInPlaceSync(data.AsSpan());

            Assert.Equal(original.Length, data.Length);
            Assert.Equal(original, data);
            Log($"Kusumi512_EncryptInPlaceSync_RoundTrip passed: original length={original.Length}, data length={data.Length}");
        }

        [Fact]
        public void Kusumi512Poly1305_EncryptInPlace_ThrowsNotSupported()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);
            using var cipher = CryptoFactory.CreateKusumi512Poly1305(key, nonce);
            byte[] buffer = new byte[4096];

            Assert.Throws<NotSupportedException>(() => cipher.EncryptInPlaceSync(buffer.AsSpan()));
            Assert.ThrowsAsync<NotSupportedException>(() => cipher.EncryptInPlace(buffer.AsMemory()));
            Log("Kusumi512Poly1305_EncryptInPlace_ThrowsNotSupported passed");
        }

        [Fact]
        public void CreateKusumi512_InvalidKeyLength_Throws()
        {
            byte[] key = new byte[63]; // Invalid length
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);

            Assert.Throws<ArgumentException>(() => CryptoFactory.CreateKusumi512(key, nonce));
            Log("CreateKusumi512_InvalidKeyLength_Throws passed");
        }

        [Fact]
        public void CreateKusumi512Poly1305_InvalidKeyLength_Throws()
        {
            byte[] key = new byte[63]; // Invalid length
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);

            Assert.Throws<ArgumentException>(() => CryptoFactory.CreateKusumi512Poly1305(key, nonce));
            Log("CreateKusumi512Poly1305_InvalidKeyLength_Throws passed");
        }

        [Fact]
        public void GenerateKey_Kusumi512_Returns64Bytes()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            Assert.Equal(64, key.Length);
            Log("GenerateKey_Kusumi512_Returns64Bytes passed");
        }

        [Fact]
        public void GenerateKey_Kusumi512Poly1305_Returns64Bytes()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512Poly1305);
            Assert.Equal(64, key.Length);
            Log("GenerateKey_Kusumi512Poly1305_Returns64Bytes passed");
        }

        [Fact]
        public void GenerateNonce_Kusumi512_Returns12Bytes()
        {
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            Assert.Equal(12, nonce.Length);
            Log("GenerateNonce_Kusumi512_Returns12Bytes passed");
        }

        [Fact]
        public void GenerateNonce_Kusumi512Poly1305_Returns12Bytes()
        {
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512Poly1305);
            Assert.Equal(12, nonce.Length);
            Log("GenerateNonce_Kusumi512Poly1305_Returns12Bytes passed");
        }
    }
}