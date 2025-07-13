using GreenfieldPQC.Cryptography;
using GreenfieldPQC.Cryptography.Parameters;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using static GreenfieldPQC.Cryptography.CryptoFactory;

namespace GreenfieldPQC.Tests
{
    public class Kusumi512Tests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(Path.GetTempPath(), "kusumi512_test_log.txt");

        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }

        [Fact]
        public async Task Encrypt_RoundTrip_ReturnsOriginal()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, Kusumi-512!");

            byte[] ciphertext = await cipher.Encrypt(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] decrypted = await decryptCipher.Decrypt(ciphertext);

            Assert.Equal(plaintext, decrypted);
            Assert.NotSame(plaintext, ciphertext);
            Log("Kusumi512_Encrypt_RoundTrip passed");
        }

        [Fact]
        public async Task EncryptAsync_RoundTrip()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] plaintext = Encoding.UTF8.GetBytes("Hello, Kusumi-512!");

            byte[] ciphertext = await cipher.Encrypt(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] decrypted = await decryptCipher.Decrypt(ciphertext);

            Assert.Equal(plaintext, decrypted);
            Assert.NotSame(plaintext, ciphertext);
            Log("Kusumi512_EncryptAsync_RoundTrip passed");
        }

        [Fact]
        public async Task Encrypt_NullInput_ThrowsArgumentNullException()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);

            await Assert.ThrowsAsync<ArgumentNullException>(() => cipher.Encrypt(null));
            Log("Kusumi512_Encrypt_NullInput_Throws passed");
        }

        [Fact]
        public void Constructor_InvalidKeyLength_ThrowsArgumentException()
        {
            byte[] key = new byte[32]; // Wrong length
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);

            Assert.Throws<ArgumentException>(() => new Kusumi512(key, nonce));
            Log("Kusumi512_Constructor_InvalidKeyLength_Throws passed");
        }

        [Fact]
        public async Task EncryptInPlace_RoundTrip_ReturnsOriginal()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] data = Encoding.UTF8.GetBytes("Hello, Kusumi-512!");
            byte[] buffer = data.ToArray();

            await cipher.EncryptInPlace(buffer.AsMemory());
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            await decryptCipher.DecryptInPlace(buffer.AsMemory());

            Assert.Equal(data, buffer);
            Log("Kusumi512_EncryptInPlace_RoundTrip passed");
        }

        [Fact]
        public void EncryptInPlaceSync_RoundTrip_ReturnsOriginal()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] data = Encoding.UTF8.GetBytes("Hello, Kusumi-512!");
            byte[] buffer = data.ToArray();

            cipher.EncryptInPlaceSync(buffer.AsSpan());
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            decryptCipher.DecryptInPlaceSync(buffer.AsSpan());

            Assert.Equal(data, buffer);
            Log("Kusumi512_EncryptInPlaceSync_RoundTrip passed");
        }

        [Fact]
        public async Task EncryptStream_RoundTrip_ReturnsOriginal()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] data = new byte[8192];
            RandomNumberGenerator.Fill(data);

            using var input = new MemoryStream(data);
            using var encrypted = new MemoryStream();
            using var decrypted = new MemoryStream();
            await cipher.EncryptStream(input, encrypted, 4096);
            encrypted.Position = 0;
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            await decryptCipher.DecryptStream(encrypted, decrypted, 4096);

            Assert.Equal(data, decrypted.ToArray());
            Log("Kusumi512_EncryptStream_RoundTrip passed");
        }

        [Fact]
        public void EncryptStreamSync_RoundTrip_ReturnsOriginal()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] data = new byte[8192];
            RandomNumberGenerator.Fill(data);

            using var input = new MemoryStream(data);
            using var encrypted = new MemoryStream();
            using var decrypted = new MemoryStream();
            cipher.EncryptStreamSync(input, encrypted, 4096);
            encrypted.Position = 0;
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            decryptCipher.DecryptStreamSync(encrypted, decrypted, 4096);

            Assert.Equal(data, decrypted.ToArray());
            Log("Kusumi512_EncryptStreamSync_RoundTrip passed");
        }

        [Fact]
        public async Task EncryptStream_Cancel_ThrowsTaskCanceledException()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            using var input = new MemoryStream(new byte[8192]);
            using var output = new MemoryStream();
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAsync<TaskCanceledException>(() => cipher.EncryptStream(input, output, 4096, null, null, null, cts.Token));
            Log("Kusumi512_EncryptStream_Cancel_Throws passed");
        }

        [Fact]
        public void EncryptInPlace_Word24_AffectsKeystream()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce1 = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            byte[] nonce2 = nonce1.ToArray(); nonce2[8] = 1; // Change byte in nonce affecting word 24
            byte[] buffer1 = new byte[100];
            byte[] buffer2 = new byte[100];
            using var cipher1 = CryptoFactory.CreateKusumi512(key, nonce1);
            using var cipher2 = CryptoFactory.CreateKusumi512(key, nonce2);

            cipher1.EncryptInPlaceSync(buffer1.AsSpan());
            cipher2.EncryptInPlaceSync(buffer2.AsSpan());

            Assert.NotEqual(buffer1, buffer2);
            Log("Kusumi512_EncryptInPlace_Word24_AffectsKeystream passed");
        }

        [Fact]
        public async Task EncryptInPlace_NullInput_ThrowsArgumentNullException()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);

            await Assert.ThrowsAsync<ArgumentNullException>(() => cipher.EncryptInPlace(null));
            Log("Kusumi512_EncryptInPlace_NullInput_Throws passed");
        }

        [Fact]
        public void EncryptStream_NullInput_ThrowsArgumentNullException()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            using var output = new MemoryStream();

            Assert.Throws<ArgumentNullException>(() => cipher.EncryptStreamSync(null, output));
            Log("Kusumi512_EncryptStream_NullInput_Throws passed");
        }

        [Fact]
        public void JohnDonneRoundTrips()
        {
            string keyHex = "0e227b328679aa128aa844c3d25a79ed6dde8cfa828e997ef756bd0b4ee437387044b67997166d4504c583e864b8a33dd1a8e0834a639a6e8bb28568ee85ef5f";
            string nonceHex = "9927a415541d834163a34677";
            string ciphertextHex = "c639453f06410004de17b6b93ac9c9d3321e4146642444e31c359674a3ce1d7e42c035d1da38786b043be9c9bf280ed78b061c4902a78c57c5bd6a78f700ce8fb0ef223524ed46ed7070755897b90a3891e510194a95f4319b60dfc6d5dd118519b6d50c0a42e8756111f706807612761b75f8ab8e612d4f20cfb895993236720c236d64e76a777f5b0a086d9e7febb0a4ecee2cc28532659855a9d0bd519492814fd488654bd98e3ac7a03cffc8c1177215e457a1b8ddacf227c40208eedfea050f45d99fd4b2dd2e5ac9fef80988a049ee593d0f9e291285104655ad8ea4801e4b002b9dd852c54fd6e3f9d4e66e947c211d4a397506da0a10a42d154380691920c9baf14e5253590fa517152f0ed435616d5095d05e3a619e55590f710921bf5cb76b9b2aa9b88e92a90d4e195f1babaa8a92430ec43f56bb6036032d6b6cd7f48642331f1eb06df89d3c76b2394d996a2bf6fd873b47530f01d2517da6c3c6937e3dc94584b95dc63d8e2ba11f77fbdb4521e075c0711577914b6f5183b8e83cfd5689";
            byte[] key = Convert.FromHexString(keyHex);
            byte[] nonce = Convert.FromHexString(nonceHex);
            byte[] expectedCiphertext = Convert.FromHexString(ciphertextHex);

            byte[] plaintext = Encoding.UTF8.GetBytes("No man is an island, entire of itself; every man is a piece of the continent, a part of the main. If a clod be washed away by the sea, Europe is the less, as well as if a promontory were, as well as if a manor of thy friend's or of thine own were: any man's death diminishes me, because I am involved in mankind, and therefore never send to know for whom the bell tolls; it tolls for thee.");
            using var cipher = new Kusumi512(key, nonce);

            byte[] ciphertext1 = cipher.EncryptSync(plaintext);
            try
            {
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "kusumi512_actual_ciphertext.txt"), Convert.ToHexString(ciphertext1).ToLower());
                Log("Kusumi512 Actual Ciphertext written successfully");
            }
            catch (Exception ex)
            {
                Log($"Kusumi512 Actual Ciphertext File Write Error: {ex.Message}");
            }
            using var decryptCipher1 = new Kusumi512(key, nonce);
            byte[] decrypted1 = decryptCipher1.DecryptSync(ciphertext1);
            Assert.Equal(plaintext, decrypted1);
            Assert.Equal(expectedCiphertext, ciphertext1);

            using var cipher2 = new Kusumi512(key, nonce);
            byte[] ciphertext2 = cipher2.EncryptSync(plaintext);
            using var decryptCipher2 = new Kusumi512(key, nonce);
            byte[] decrypted2 = decryptCipher2.DecryptSync(ciphertext2);
            Assert.Equal(plaintext, decrypted2);
            Assert.Equal(expectedCiphertext, ciphertext2);

            Assert.Equal(ciphertext1, ciphertext2);
            Log("Kusumi512_JohnDonneRoundTrips passed");
        }
    }

    public class SHA256Tests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(Path.GetTempPath(), "sha256_test_log.txt");

        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }

        [Fact]
        public async Task Hash_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            byte[] expected = Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

            byte[] hash = CryptoFactory.ComputeSHA256(input);

            Assert.Equal(expected, hash);
            Log("SHA256_Hash_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public void HashSync_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            byte[] expected = Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

            byte[] hash = CryptoFactory.ComputeSHA256(input);

            Assert.Equal(expected, hash);
            Log("SHA256_HashSync_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public async Task HashStream_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            using var stream = new MemoryStream(input);
            byte[] expected = Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

            byte[] hash = CryptoFactory.ComputeSHA256(input);

            Assert.Equal(expected, hash);
            Log("SHA256_HashStream_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public void HashStreamSync_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            using var stream = new MemoryStream(input);
            byte[] expected = Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

            byte[] hash = CryptoFactory.ComputeSHA256(input);

            Assert.Equal(expected, hash);
            Log("SHA256_HashStreamSync_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public void Hash_NullInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => CryptoFactory.ComputeSHA256(null));
            Log("SHA256_Hash_NullInput_Throws passed");
        }
    }

    public class SHA512Tests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(Path.GetTempPath(), "sha512_test_log.txt");

        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }

        [Fact]
        public async Task Hash_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            byte[] expected = Convert.FromHexString("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

            byte[] hash = CryptoFactory.ComputeSHA512(input);

            Assert.Equal(expected, hash);
            Log("SHA512_Hash_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public void HashSync_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            byte[] expected = Convert.FromHexString("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

            byte[] hash = CryptoFactory.ComputeSHA512(input);

            Assert.Equal(expected, hash);
            Log("SHA512_HashSync_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public async Task HashStream_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            using var stream = new MemoryStream(input);
            byte[] expected = Convert.FromHexString("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

            byte[] hash = CryptoFactory.ComputeSHA512(input);

            Assert.Equal(expected, hash);
            Log("SHA512_HashStream_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public void HashStreamSync_KnownInput_MatchesExpected()
        {
            byte[] input = Encoding.UTF8.GetBytes("abc");
            using var stream = new MemoryStream(input);
            byte[] expected = Convert.FromHexString("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

            byte[] hash = CryptoFactory.ComputeSHA512(input);

            Assert.Equal(expected, hash);
            Log("SHA512_HashStreamSync_KnownInput_MatchesExpected passed");
        }

        [Fact]
        public void Hash_NullInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => CryptoFactory.ComputeSHA512(null));
            Log("SHA512_Hash_NullInput_Throws passed");
        }
    }

    public class KyberTests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(Path.GetTempPath(), "kyber_test_log.txt");

        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }

        [Fact]
        public async Task GenerateKeyPair_EncapsulateDecapsulate_RoundTrip()
        {
            using var kyber = new Kyber(new KyberParameters(512));
            var (publicKey, privateKey) = kyber.GenerateKeyPairSync();
            var (sharedSecret1, ciphertext) = kyber.EncapsulateSync(publicKey);
            byte[] sharedSecret2 = await kyber.Decapsulate(ciphertext, privateKey);

            Assert.NotNull(publicKey);
            Assert.NotNull(privateKey);
            Assert.NotNull(sharedSecret1);
            Assert.NotNull(ciphertext);
            Assert.Equal(sharedSecret1, sharedSecret2);
            Log("Kyber_GenerateKeyPair_EncapsulateDecapsulate_RoundTrip passed");
        }

        [Fact]
        public void Constructor_NullParameters_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new Kyber(null));
            Log("Kyber_Constructor_NullParameters_Throws passed");
        }
    }

    public class DilithiumTests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(Path.GetTempPath(), "dilithium_test_log.txt");

        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }

        [Fact]
        public async Task GenerateKeyPair_SignVerify_ValidSignature()
        {
            using var dilithium = new Dilithium(new DilithiumParameters(2));
            var (publicKey, privateKey) = dilithium.GenerateKeyPairSync();
            byte[] message = Encoding.UTF8.GetBytes("Hello, Dilithium!");
            byte[] signature = await dilithium.Sign(message, privateKey);

            bool isValid = await dilithium.Verify(message, signature, publicKey);

            Assert.True(isValid);
            Assert.NotNull(publicKey);
            Assert.NotNull(privateKey);
            Assert.NotNull(signature);
            Log("Dilithium_GenerateKeyPair_SignVerify_ValidSignature passed");
        }

        [Fact]
        public void VerifySync_InvalidSignature_ReturnsFalse()
        {
            using var dilithium = new Dilithium(new DilithiumParameters(2));
            var (publicKey, privateKey) = dilithium.GenerateKeyPairSync();
            byte[] message = Encoding.UTF8.GetBytes("Hello, Dilithium!");
            byte[] signature = new byte[dilithium.GetSignatureLength()];
            RandomNumberGenerator.Fill(signature); // Invalid signature

            bool isValid = dilithium.VerifySync(message, signature, publicKey);

            Assert.False(isValid);
            Log("Dilithium_VerifySync_InvalidSignature_ReturnsFalse passed");
        }

        [Fact]
        public void Constructor_NullParameters_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new Dilithium(null));
            Log("Dilithium_Constructor_NullParameters_Throws passed");
        }
    }

    public class CryptoFactoryTests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(Path.GetTempPath(), "cryptofactory_test_log.txt");

        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }

        [Fact]
        public void CreateKusumi512_ReturnsKusumi512()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            Assert.IsType<Kusumi512>(cipher);
            Assert.Equal("Kusumi512", cipher.AlgorithmName);
            Log("CryptoFactory_CreateKusumi512_ReturnsKusumi512 passed");
        }

        [Fact]
        public void CreateKyber_ReturnsKyber()
        {
            using var kyber = new Kyber(new KyberParameters(512));
            Assert.IsType<Kyber>(kyber);
            Assert.Equal("Kyber-512", kyber.AlgorithmName);
            Log("CryptoFactory_CreateKyber_ReturnsKyber passed");
        }

        [Fact]
        public void CreateDilithium_ReturnsDilithium()
        {
            using var dilithium = new Dilithium(new DilithiumParameters(2));
            Assert.IsType<Dilithium>(dilithium);
            Assert.Equal("Dilithium-2", dilithium.AlgorithmName);
            Log("CryptoFactory_CreateDilithium_ReturnsDilithium passed");
        }

        [Fact]
        public void GenerateKey_Kusumi512_Returns64Bytes()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            Assert.Equal(64, key.Length);
            Log("CryptoFactory_GenerateKey_Kusumi512_Returns64Bytes passed");
        }

        [Fact]
        public void GenerateKey_UnknownAlgorithm_ThrowsArgumentOutOfRangeException()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => CryptoFactory.GenerateKey((CipherAlgorithm)999));
            Log("CryptoFactory_GenerateKey_UnknownAlgorithm_Throws passed");
        }

        [Fact]
        public void GenerateNonce_Kusumi512_Returns12Bytes()
        {
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            Assert.Equal(12, nonce.Length);
            Log("CryptoFactory_GenerateNonce_Kusumi512_Returns12Bytes passed");
        }
    }
}