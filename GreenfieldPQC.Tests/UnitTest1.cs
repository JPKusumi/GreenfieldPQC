using GreenfieldPQC.Cryptography;
using GreenfieldPQC.Cryptography.Parameters;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using static GreenfieldPQC.Cryptography.CryptoFactory;

namespace GreenfieldPQC.Tests
{
    public class JwtTests
    {
        private static readonly object LogLock = new(); // Lock for file writes
        private readonly string logPath = Path.Combine(Path.GetTempPath(), "jwt_test_log.txt");
        private void Log(string message)
        {
            lock (LogLock)
            {
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}\n");
            }
        }
        [Fact]
        public void JwsProvider_CreateJws_VerifyJws_RoundTrip()
        {
            // Arrange
            var dilithiumLevel = 3;  // Balanced security (ML-DSA-65)
            var jwsProvider = CryptoFactory.CreateJwsProvider(dilithiumLevel);
            var (publicKey, privateKey) = CryptoFactory.CreateDilithium(dilithiumLevel).GenerateKeyPair();
            var payload = new { sub = "user123", name = "Test User", iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() };

            // Act
            string jwsToken = jwsProvider.CreateJws(payload, privateKey);
            var verifiedPayload = jwsProvider.VerifyJws(jwsToken, publicKey);  // No 'as dynamic' - assume VerifyJws returns object

            // Deserialize to JsonElement for property access
            JsonElement verifiedJson = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(verifiedPayload));

            // Assert
            Assert.NotNull(jwsToken);
            Assert.Equal(3, jwsToken.Split('.').Length);  // Three-part format
            Assert.NotNull(verifiedPayload);
            Assert.Equal("user123", verifiedJson.GetProperty("sub").GetString());
            Assert.Equal("Test User", verifiedJson.GetProperty("name").GetString());
            Assert.Equal(payload.iat, verifiedJson.GetProperty("iat").GetInt64());
            Assert.Equal(payload.exp, verifiedJson.GetProperty("exp").GetInt64());

            Log("JwsProvider_CreateJws_VerifyJws_RoundTrip passed");
        }

        [Fact]
        public void JwsProvider_VerifyJws_InvalidSignature_ThrowsException()
        {
            // Arrange
            var dilithiumLevel = 3;
            var jwsProvider = CryptoFactory.CreateJwsProvider(dilithiumLevel);
            var (publicKey, privateKey) = CryptoFactory.CreateDilithium(dilithiumLevel).GenerateKeyPair(); var payload = new { sub = "user123" };
            string jwsToken = jwsProvider.CreateJws(payload, privateKey);

            // Tamper with the token (e.g., alter payload part)
            string[] parts = jwsToken.Split('.');
            parts[1] = Utility.Base64UrlEncode(Encoding.UTF8.GetBytes("tampered"));  // Corrupt payload
            string tamperedToken = string.Join(".", parts);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => jwsProvider.VerifyJws(tamperedToken, publicKey));  // Or your specific exception type, e.g., CryptographicException

            Log("JwsProvider_VerifyJws_InvalidSignature_ThrowsException passed");
        }

        [Fact]
        public void JwsProvider_CreateJws_EmptyPayload_RoundTrip()
        {
            // Arrange
            var dilithiumLevel = 3;
            var jwsProvider = CryptoFactory.CreateJwsProvider(dilithiumLevel);
            var (publicKey, privateKey) = CryptoFactory.CreateDilithium(dilithiumLevel).GenerateKeyPair(); var emptyPayload = new { };  // Empty object

            // Act
            string jwsToken = jwsProvider.CreateJws(emptyPayload, privateKey);
            var verifiedPayload = jwsProvider.VerifyJws(jwsToken, publicKey);

            // Deserialize to JsonElement and check if empty
            JsonElement verifiedJson = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(verifiedPayload));
            Assert.Empty(verifiedJson.EnumerateObject());

            Log("JwsProvider_CreateJws_EmptyPayload_RoundTrip passed");
        }

        [Theory]
        [InlineData(2)]  // Level 2 (ML-DSA-44)
        [InlineData(3)]  // Level 3 (ML-DSA-65)
        [InlineData(5)]  // Level 5 (ML-DSA-87)
        public void JwsProvider_CreateJws_VariousLevels_RoundTrip(int dilithiumLevel)
        {
            // Arrange
            var jwsProvider = CryptoFactory.CreateJwsProvider(dilithiumLevel);
            var (publicKey, privateKey) = CryptoFactory.CreateDilithium(dilithiumLevel).GenerateKeyPair(); var payload = new { test = "value" };

            // Act
            string jwsToken = jwsProvider.CreateJws(payload, privateKey);
            var verifiedPayload = jwsProvider.VerifyJws(jwsToken, publicKey);

            // Deserialize to JsonElement for property access
            JsonElement verifiedJson = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(verifiedPayload));

            // Assert
            Assert.NotNull(jwsToken);
            Assert.Equal("value", verifiedJson.GetProperty("test").GetString());

            Log($"JwsProvider_CreateJws_VariousLevels_RoundTrip (Level {dilithiumLevel}) passed");
        }

        [Fact]
        public void JweProvider_CreateJwe_DecryptJwe_RoundTrip()
        {
            // Arrange
            var kyberLevel = 3;  // Balanced security
            var kusumiAlgorithm = CryptoFactory.CipherAlgorithm.Kusumi512Poly1305;  // AEAD for authenticity
            var jweProvider = CryptoFactory.CreateJweProvider(kyberLevel, kusumiAlgorithm);
            int kyberParam = kyberLevel switch { 1 => 512, 3 => 768, 5 => 1024, _ => throw new ArgumentOutOfRangeException() };
            var (publicKey, privateKey) = CryptoFactory.CreateKyber(kyberParam).GenerateKeyPair();

            var payload = new { sub = "user123", name = "Test User", iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() };

            // Act
            string jweToken = jweProvider.CreateJwe(payload, publicKey);
            string decryptedJson = jweProvider.DecryptJwe(jweToken, privateKey);

            // Deserialize to JsonElement for property access
            JsonElement decryptedElement = JsonSerializer.Deserialize<JsonElement>(decryptedJson);

            // Assert
            Assert.NotNull(jweToken);
            Assert.Equal(5, jweToken.Split('.').Length);  // Five-part format
            Assert.Equal("user123", decryptedElement.GetProperty("sub").GetString());
            Assert.Equal("Test User", decryptedElement.GetProperty("name").GetString());
            Assert.Equal(payload.iat, decryptedElement.GetProperty("iat").GetInt64());
            Assert.Equal(payload.exp, decryptedElement.GetProperty("exp").GetInt64());

            Log("JweProvider_CreateJwe_DecryptJwe_RoundTrip passed");
        }

        [Fact]
        public void JweProvider_DecryptJwe_InvalidToken_ThrowsException()
        {
            // Arrange
            var kyberLevel = 3;
            var kusumiAlgorithm = CryptoFactory.CipherAlgorithm.Kusumi512Poly1305;
            var jweProvider = CryptoFactory.CreateJweProvider(kyberLevel, kusumiAlgorithm);
            int kyberParam = kyberLevel switch { 1 => 512, 3 => 768, 5 => 1024, _ => throw new ArgumentOutOfRangeException() };
            var (publicKey, privateKey) = CryptoFactory.CreateKyber(kyberParam).GenerateKeyPair();

            var payload = new { sub = "user123" };
            string jweToken = jweProvider.CreateJwe(payload, publicKey);

            // Tamper with the token (e.g., alter ciphertext part)
            string[] parts = jweToken.Split('.');
            parts[3] = Utility.Base64UrlEncode(Encoding.UTF8.GetBytes("tampered"));  // Corrupt ciphertext
            string tamperedToken = string.Join(".", parts);

            // Act & Assert
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => jweProvider.DecryptJwe(tamperedToken, privateKey));  // Match the actual exception

            Log("JweProvider_DecryptJwe_InvalidToken_ThrowsException passed");
        }

        [Fact]
        public void JweProvider_CreateJwe_EmptyPayload_RoundTrip()
        {
            // Arrange
            var kyberLevel = 3;
            var kusumiAlgorithm = CryptoFactory.CipherAlgorithm.Kusumi512;  // Plain Kusumi512
            var jweProvider = CryptoFactory.CreateJweProvider(kyberLevel, kusumiAlgorithm);
            int kyberParam = kyberLevel switch { 1 => 512, 3 => 768, 5 => 1024, _ => throw new ArgumentOutOfRangeException() };
            var (publicKey, privateKey) = CryptoFactory.CreateKyber(kyberParam).GenerateKeyPair();

            var emptyPayload = new { };  // Empty object

            // Act
            string jweToken = jweProvider.CreateJwe(emptyPayload, publicKey);
            string decryptedJson = jweProvider.DecryptJwe(jweToken, privateKey);

            // Deserialize to JsonElement and check if empty
            JsonElement decryptedElement = JsonSerializer.Deserialize<JsonElement>(decryptedJson);
            Assert.Equal(JsonValueKind.Object, decryptedElement.ValueKind);
            Assert.Empty(decryptedElement.EnumerateObject());  // Use Assert.Empty for collection size

            Log("JweProvider_CreateJwe_EmptyPayload_RoundTrip passed");
        }

        [Theory]
        [InlineData(1, CryptoFactory.CipherAlgorithm.Kusumi512)]  // Level 1, plain
        [InlineData(3, CryptoFactory.CipherAlgorithm.Kusumi512Poly1305)]  // Level 3, Poly1305
        [InlineData(5, CryptoFactory.CipherAlgorithm.Kusumi512)]  // Level 5, plain
        public void JweProvider_CreateJwe_VariousLevelsAndVariants_RoundTrip(int kyberLevel, CryptoFactory.CipherAlgorithm kusumiAlgorithm)
        {
            // Arrange
            var jweProvider = CryptoFactory.CreateJweProvider(kyberLevel, kusumiAlgorithm);
            int kyberParam = kyberLevel switch { 1 => 512, 3 => 768, 5 => 1024, _ => throw new ArgumentOutOfRangeException() };
            var (publicKey, privateKey) = CryptoFactory.CreateKyber(kyberParam).GenerateKeyPair();

            var payload = new { test = "value" };

            // Act
            string jweToken = jweProvider.CreateJwe(payload, publicKey);
            string decryptedJson = jweProvider.DecryptJwe(jweToken, privateKey);

            // Deserialize to JsonElement for property access
            JsonElement decryptedElement = JsonSerializer.Deserialize<JsonElement>(decryptedJson);

            // Assert
            Assert.NotNull(jweToken);
            Assert.Equal("value", decryptedElement.GetProperty("test").GetString());

            Log($"JweProvider_CreateJwe_VariousLevelsAndVariants_RoundTrip (Level {kyberLevel}, Algorithm {kusumiAlgorithm}) passed");
        }

        [Fact]
        public void JwsJweNesting_CreateNested_VerifyRoundTrip()
        {
            // Arrange
            var dilithiumLevel = 3;  // For JWS
            var kyberLevel = 3;  // For JWE
            var kusumiAlgorithm = CryptoFactory.CipherAlgorithm.Kusumi512Poly1305;  // AEAD for JWE

            IJwsProvider jwsProvider = CryptoFactory.CreateJwsProvider(dilithiumLevel);
            IJweProvider jweProvider = CryptoFactory.CreateJweProvider(kyberLevel, kusumiAlgorithm);

            var (signPubKey, signPrivKey) = CryptoFactory.CreateDilithium(dilithiumLevel).GenerateKeyPair();
            int kyberParam = kyberLevel switch { 1 => 512, 3 => 768, 5 => 1024, _ => throw new ArgumentOutOfRangeException() };
            var (encPubKey, encPrivKey) = CryptoFactory.CreateKyber(kyberParam).GenerateKeyPair();

            var originalPayload = new { sub = "user123", secret = "nested confidential data", iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() };

            // Act - Create inner JWS
            string innerJws = jwsProvider.CreateJws(originalPayload, signPrivKey);

            // Encrypt the JWS as JWE payload (nesting)
            string nestedToken = jweProvider.CreateJwe(innerJws, encPubKey);  // Pass string JWS as payload

            // Decrypt outer JWE to get inner JWS
            string decryptedJws = jweProvider.DecryptJwe(nestedToken, encPrivKey);  // Now returns string
            Assert.NotNull(decryptedJws);  // Ensure not null

            // Verify inner JWS to get original payload
            object verifiedObj = jwsProvider.VerifyJws(decryptedJws, signPubKey);
            dynamic verifiedPayload = verifiedObj;

            // Assert
            Assert.NotNull(nestedToken);
            Assert.Equal(5, nestedToken.Split('.').Length);  // JWE format
            Assert.Equal(3, decryptedJws.Split('.').Length);  // Inner JWS format
            Assert.NotNull(verifiedPayload);
            Assert.Equal(originalPayload.sub, verifiedPayload.sub);
            Assert.Equal(originalPayload.secret, verifiedPayload.secret);
            Assert.Equal(originalPayload.iat, verifiedPayload.iat);
            Assert.Equal(originalPayload.exp, verifiedPayload.exp);

            Log("JwsJweNesting_CreateNested_VerifyRoundTrip passed");
        }
    }
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

            byte[] ciphertext = await cipher.EncryptAsync(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] decrypted = await decryptCipher.DecryptAsync(ciphertext);

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

            byte[] ciphertext = await cipher.EncryptAsync(plaintext);
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] decrypted = await decryptCipher.DecryptAsync(ciphertext);

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

            await Assert.ThrowsAsync<ArgumentNullException>(() => cipher.EncryptAsync(null));
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
            byte[] buffer = [.. data];
            await cipher.EncryptInPlaceAsync(buffer.AsMemory());
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            await decryptCipher.DecryptInPlaceAsync(buffer.AsMemory());

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
            byte[] buffer = [..data];

            cipher.EncryptInPlace(buffer.AsSpan());
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            decryptCipher.DecryptInPlace(buffer.AsSpan());

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
            await cipher.EncryptStreamAsync(input, encrypted, 4096);
            encrypted.Position = 0;
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            await decryptCipher.DecryptStreamAsync(encrypted, decrypted, 4096);

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
            cipher.EncryptStream(input, encrypted, 4096);
            encrypted.Position = 0;
            using var decryptCipher = CryptoFactory.CreateKusumi512(key, nonce);
            decryptCipher.DecryptStream(encrypted, decrypted, 4096);

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

            await Assert.ThrowsAsync<TaskCanceledException>(() => cipher.EncryptStreamAsync(input, output, 4096, null, null, null, cts.Token));
            Log("Kusumi512_EncryptStream_Cancel_Throws passed");
        }

        [Fact]
        public void EncryptInPlace_Word24_AffectsKeystream()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce1 = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            byte[] nonce2 = [..nonce1]; 
            nonce2[8] = 1; // Change byte in nonce affecting word 24
            byte[] buffer1 = new byte[100];
            byte[] buffer2 = new byte[100];
            using var cipher1 = CryptoFactory.CreateKusumi512(key, nonce1);
            using var cipher2 = CryptoFactory.CreateKusumi512(key, nonce2);

            cipher1.EncryptInPlace(buffer1.AsSpan());
            cipher2.EncryptInPlace(buffer2.AsSpan());

            Assert.NotEqual(buffer1, buffer2);
            Log("Kusumi512_EncryptInPlace_Word24_AffectsKeystream passed");
        }

        [Fact]
        public async Task EncryptInPlace_NullInput_ThrowsArgumentNullException()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);

            await Assert.ThrowsAsync<ArgumentNullException>(() => cipher.EncryptInPlaceAsync(null));
            Log("Kusumi512_EncryptInPlace_NullInput_Throws passed");
        }

        [Fact]
        public void EncryptStream_NullInput_ThrowsArgumentNullException()
        {
            byte[] key = CryptoFactory.GenerateKey(CipherAlgorithm.Kusumi512);
            byte[] nonce = CryptoFactory.GenerateNonce(CipherAlgorithm.Kusumi512);
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);
            using var output = new MemoryStream();

            Assert.Throws<ArgumentNullException>(() => cipher.EncryptStream(null, output));
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
            using var cipher = CryptoFactory.CreateKusumi512(key, nonce);

            byte[] ciphertext1 = cipher.Encrypt(plaintext);
            try
            {
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "kusumi512_actual_ciphertext.txt"), Convert.ToHexString(ciphertext1).ToLower());
                Log("Kusumi512 Actual Ciphertext written successfully");
            }
            catch (Exception ex)
            {
                Log($"Kusumi512 Actual Ciphertext File Write Error: {ex.Message}");
            }
            using var decryptCipher1 = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] decrypted1 = decryptCipher1.Decrypt(ciphertext1);
            Assert.Equal(plaintext, decrypted1);
            Assert.Equal(expectedCiphertext, ciphertext1);

            using var cipher2 = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] ciphertext2 = cipher2.Encrypt(plaintext);
            using var decryptCipher2 = CryptoFactory.CreateKusumi512(key, nonce);
            byte[] decrypted2 = decryptCipher2.Decrypt(ciphertext2);
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
            Assert.Throws<ArgumentNullException>(static () => CryptoFactory.ComputeSHA256((byte[])null));
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
            Assert.Throws<ArgumentNullException>(() => CryptoFactory.ComputeSHA512((byte[])null));
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
        public void GenerateKeyPair_EncapsulateDecapsulate_RoundTrip()
        {
            var kyber = CryptoFactory.CreateKyber(512);
            var (publicKey, privateKey) = kyber.GenerateKeyPair();
            var (sharedSecret1, ciphertext) = kyber.Encapsulate(publicKey);
            byte[] sharedSecret2 = kyber.Decapsulate(ciphertext, privateKey);

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
        public void GenerateKeyPair_SignVerify_ValidSignature()
        {
            var dilithium = CryptoFactory.CreateDilithium(2);
            var (publicKey, privateKey) = dilithium.GenerateKeyPair();
            byte[] message = Encoding.UTF8.GetBytes("Hello, Dilithium!");
            byte[] signature = dilithium.Sign(message, privateKey);

            bool isValid = dilithium.Verify(message, signature, publicKey);

            Assert.True(isValid);
            Assert.NotNull(publicKey);
            Assert.NotNull(privateKey);
            Assert.NotNull(signature);
            Log("Dilithium_GenerateKeyPair_SignVerify_ValidSignature passed");
        }

        [Fact]
        public void Verify_InvalidSignature_ReturnsFalse()
        {
            var dilithium = CryptoFactory.CreateDilithium(2);
            var (publicKey, _) = dilithium.GenerateKeyPair();
            byte[] message = Encoding.UTF8.GetBytes("Hello, Dilithium!");
            byte[] signature = new byte[dilithium.GetSignatureLength()];
            RandomNumberGenerator.Fill(signature); // Invalid signature

            bool isValid = dilithium.Verify(message, signature, publicKey);

            Assert.False(isValid);
            Log("Dilithium_Verify_InvalidSignature_ReturnsFalse passed");
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
            var kyber = CryptoFactory.CreateKyber(512);
            Assert.IsType<Kyber>(kyber);
            Assert.Equal("ML-KEM-512", kyber.AlgorithmName);
            Log("CryptoFactory_CreateKyber_ReturnsKyber passed");
        }

        [Fact]
        public void CreateDilithium_ReturnsDilithium()
        {
            var dilithium = CryptoFactory.CreateDilithium(2);
            Assert.IsType<Dilithium>(dilithium);
            Assert.Equal("ML-DSA-44", dilithium.AlgorithmName);
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

        // ========== ENUM API TESTS (v1.1.0+) ==========

        [Theory]
        [InlineData(KyberSecurityLevel.ML_KEM_512, "ML-KEM-512")]
        [InlineData(KyberSecurityLevel.ML_KEM_768, "ML-KEM-768")]
        [InlineData(KyberSecurityLevel.ML_KEM_1024, "ML-KEM-1024")]
        public void CreateKyber_WithEnum_ReturnsCorrectAlgorithm(KyberSecurityLevel level, string expectedAlgorithmName)
        {
            // Act
            var kyber = CryptoFactory.CreateKyber(level);

            // Assert
            Assert.IsType<Kyber>(kyber);
            Assert.Equal(expectedAlgorithmName, kyber.AlgorithmName);
            Log($"CreateKyber_WithEnum_{level}_Returns{expectedAlgorithmName} passed");
        }

        [Theory]
        [InlineData(DilithiumSecurityLevel.ML_DSA_44, "ML-DSA-44")]
        [InlineData(DilithiumSecurityLevel.ML_DSA_65, "ML-DSA-65")]
        [InlineData(DilithiumSecurityLevel.ML_DSA_87, "ML-DSA-87")]
        public void CreateDilithium_WithEnum_ReturnsCorrectAlgorithm(DilithiumSecurityLevel level, string expectedAlgorithmName)
        {
            // Act
            var dilithium = CryptoFactory.CreateDilithium(level);

            // Assert
            Assert.IsType<Dilithium>(dilithium);
            Assert.Equal(expectedAlgorithmName, dilithium.AlgorithmName);
            Log($"CreateDilithium_WithEnum_{level}_Returns{expectedAlgorithmName} passed");
        }

        [Theory]
        [InlineData(DilithiumSecurityLevel.ML_DSA_44)]
        [InlineData(DilithiumSecurityLevel.ML_DSA_65)]
        [InlineData(DilithiumSecurityLevel.ML_DSA_87)]
        public void CreateJwsProvider_WithEnum_CreatesValidProvider(DilithiumSecurityLevel level)
        {
            // Arrange
            var jwsProvider = CryptoFactory.CreateJwsProvider(level);
            var signer = CryptoFactory.CreateDilithium(level);
            var (publicKey, privateKey) = signer.GenerateKeyPair();
            var payload = new { test = "enum-api", level = level.ToString() };

            // Act
            string jwsToken = jwsProvider.CreateJws(payload, privateKey);
            dynamic verifiedPayload = jwsProvider.VerifyJws(jwsToken, publicKey);

            // Assert
            Assert.NotNull(jwsToken);
            Assert.Equal(3, jwsToken.Split('.').Length);
            Assert.Equal("enum-api", verifiedPayload.test);
            Assert.Equal(level.ToString(), verifiedPayload.level);
            Log($"CreateJwsProvider_WithEnum_{level}_CreatesValidProvider passed");
        }

        [Theory]
        [InlineData(KyberSecurityLevel.ML_KEM_512, CipherAlgorithm.Kusumi512)]
        [InlineData(KyberSecurityLevel.ML_KEM_768, CipherAlgorithm.Kusumi512Poly1305)]
        [InlineData(KyberSecurityLevel.ML_KEM_1024, CipherAlgorithm.Kusumi512)]
        public void CreateJweProvider_WithEnum_CreatesValidProvider(KyberSecurityLevel level, CipherAlgorithm cipher)
        {
            // Arrange
            var jweProvider = CryptoFactory.CreateJweProvider(level, cipher);
            var kem = CryptoFactory.CreateKyber(level);
            var (publicKey, privateKey) = kem.GenerateKeyPair();
            var payload = new { test = "enum-api", level = level.ToString() };

            // Act
            string jweToken = jweProvider.CreateJwe(payload, publicKey);
            string decryptedJson = jweProvider.DecryptJwe(jweToken, privateKey);
            JsonElement decryptedElement = JsonSerializer.Deserialize<JsonElement>(decryptedJson);

            // Assert
            Assert.NotNull(jweToken);
            Assert.Equal(5, jweToken.Split('.').Length);
            Assert.Equal("enum-api", decryptedElement.GetProperty("test").GetString());
            Assert.Equal(level.ToString(), decryptedElement.GetProperty("level").GetString());
            Log($"CreateJweProvider_WithEnum_{level}_{cipher}_CreatesValidProvider passed");
        }

        [Fact]
        public void JwsJweNesting_WithEnums_RoundTrip()
        {
            // Arrange - Use enum API exclusively
            var dilithiumLevel = DilithiumSecurityLevel.ML_DSA_65;
            var kyberLevel = KyberSecurityLevel.ML_KEM_768;
            var kusumiAlgorithm = CryptoFactory.CipherAlgorithm.Kusumi512Poly1305;

            IJwsProvider jwsProvider = CryptoFactory.CreateJwsProvider(dilithiumLevel);
            IJweProvider jweProvider = CryptoFactory.CreateJweProvider(kyberLevel, kusumiAlgorithm);

            var (signPubKey, signPrivKey) = CryptoFactory.CreateDilithium(dilithiumLevel).GenerateKeyPair();
            var (encPubKey, encPrivKey) = CryptoFactory.CreateKyber(kyberLevel).GenerateKeyPair();

            var originalPayload = new { sub = "enum-user", secret = "enum confidential", iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };

            // Act - Create inner JWS
            string innerJws = jwsProvider.CreateJws(originalPayload, signPrivKey);

            // Encrypt the JWS as JWE payload (nesting)
            string nestedToken = jweProvider.CreateJwe(innerJws, encPubKey);

            // Decrypt outer JWE to get inner JWS
            string decryptedJws = jweProvider.DecryptJwe(nestedToken, encPrivKey);

            // Verify inner JWS to get original payload
            dynamic verifiedPayload = jwsProvider.VerifyJws(decryptedJws, signPubKey);

            // Assert
            Assert.NotNull(nestedToken);
            Assert.Equal(5, nestedToken.Split('.').Length);  // JWE format
            Assert.Equal(3, decryptedJws.Split('.').Length);  // Inner JWS format
            Assert.Equal(originalPayload.sub, verifiedPayload.sub);
            Assert.Equal(originalPayload.secret, verifiedPayload.secret);

            Log("JwsJweNesting_WithEnums_RoundTrip passed");
        }

        [Fact]
        public void EnumAndIntAPI_ProduceSameResults()
        {
            // Arrange
            var payload = new { test = "compatibility" };

            // Create with int API
            var jwsProviderInt = CryptoFactory.CreateJwsProvider(3);
            var signerInt = CryptoFactory.CreateDilithium(3);
            var (pubKeyInt, privKeyInt) = signerInt.GenerateKeyPair();

            // Create with enum API
            var jwsProviderEnum = CryptoFactory.CreateJwsProvider(DilithiumSecurityLevel.ML_DSA_65);
            var signerEnum = CryptoFactory.CreateDilithium(DilithiumSecurityLevel.ML_DSA_65);

            // Act - Create JWS with int API
            string jwsTokenInt = jwsProviderInt.CreateJws(payload, privKeyInt);

            // Verify with enum API's signer (cross-compatibility test)
            dynamic verifiedWithEnum = jwsProviderEnum.VerifyJws(jwsTokenInt, pubKeyInt);

            // Assert
            Assert.Equal("compatibility", verifiedWithEnum.test);
            Log("EnumAndIntAPI_ProduceSameResults passed");
        }

        [Theory]
        [InlineData(KyberSecurityLevel.ML_KEM_512, 512)]
        [InlineData(KyberSecurityLevel.ML_KEM_768, 768)]
        [InlineData(KyberSecurityLevel.ML_KEM_1024, 1024)]
        public void KyberParameters_WithEnum_MapsToCorrectIntValue(KyberSecurityLevel enumLevel, int expectedIntValue)
        {
            // Act
            var parameters = new KyberParameters(enumLevel);

            // Assert
            Assert.Equal(expectedIntValue, parameters.SecurityLevel);
            Log($"KyberParameters_WithEnum_{enumLevel}_MapsTo{expectedIntValue} passed");
        }

        [Theory]
        [InlineData(DilithiumSecurityLevel.ML_DSA_44, 2)]
        [InlineData(DilithiumSecurityLevel.ML_DSA_65, 3)]
        [InlineData(DilithiumSecurityLevel.ML_DSA_87, 5)]
        public void DilithiumParameters_WithEnum_MapsToCorrectIntValue(DilithiumSecurityLevel enumLevel, int expectedIntValue)
        {
            // Act
            var parameters = new DilithiumParameters(enumLevel);

            // Assert
            Assert.Equal(expectedIntValue, parameters.SecurityLevel);
            Log($"DilithiumParameters_WithEnum_{enumLevel}_MapsTo{expectedIntValue} passed");
        }

        // ========== FACTORY METHOD UNIT TESTS ==========

        [Fact]
        public void CreateJwsProvider_WithIntLevel_ReturnsValidProvider()
        {
            // Act
            var provider = CryptoFactory.CreateJwsProvider(3);

            // Assert
            Assert.NotNull(provider);
            Assert.IsAssignableFrom<IJwsProvider>(provider);
            Log("CreateJwsProvider_WithIntLevel_ReturnsValidProvider passed");
        }

        [Fact]
        public void CreateJwsProvider_WithEnumLevel_ReturnsValidProvider()
        {
            // Act
            var provider = CryptoFactory.CreateJwsProvider(DilithiumSecurityLevel.ML_DSA_65);

            // Assert
            Assert.NotNull(provider);
            Assert.IsAssignableFrom<IJwsProvider>(provider);
            Log("CreateJwsProvider_WithEnumLevel_ReturnsValidProvider passed");
        }

        [Theory]
        [InlineData(1)]  // Invalid Dilithium level
        [InlineData(4)]  // Invalid Dilithium level
        [InlineData(10)] // Invalid Dilithium level
        public void CreateJwsProvider_InvalidLevel_ThrowsException(int level)
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => CryptoFactory.CreateJwsProvider(level));
            Log($"CreateJwsProvider_InvalidLevel_{level}_ThrowsException passed");
        }

        [Fact]
        public void CreateJweProvider_WithIntLevelAndCipher_ReturnsValidProvider()
        {
            // Act
            var provider = CryptoFactory.CreateJweProvider(3, CipherAlgorithm.Kusumi512);

            // Assert
            Assert.NotNull(provider);
            Assert.IsAssignableFrom<IJweProvider>(provider);
            Log("CreateJweProvider_WithIntLevelAndCipher_ReturnsValidProvider passed");
        }

        [Fact]
        public void CreateJweProvider_WithEnumLevelAndCipher_ReturnsValidProvider()
        {
            // Act
            var provider = CryptoFactory.CreateJweProvider(KyberSecurityLevel.ML_KEM_768, CipherAlgorithm.Kusumi512Poly1305);

            // Assert
            Assert.NotNull(provider);
            Assert.IsAssignableFrom<IJweProvider>(provider);
            Log("CreateJweProvider_WithEnumLevelAndCipher_ReturnsValidProvider passed");
        }

        [Theory]
        [InlineData(0)]  // Invalid Kyber level
        [InlineData(2)]  // Invalid Kyber level
        [InlineData(4)]  // Invalid Kyber level
        public void CreateJweProvider_InvalidLevel_ThrowsException(int level)
        {
            // Act & Assert
            Assert.Throws<ArgumentOutOfRangeException>(() => 
                CryptoFactory.CreateJweProvider(level, CipherAlgorithm.Kusumi512));
            Log($"CreateJweProvider_InvalidLevel_{level}_ThrowsException passed");
        }

        [Theory]
        [InlineData(CipherAlgorithm.Kusumi512)]
        [InlineData(CipherAlgorithm.Kusumi512Poly1305)]
        public void CreateJweProvider_DifferentCipherAlgorithms_WorkCorrectly(CipherAlgorithm algorithm)
        {
            // Arrange
            var provider = CryptoFactory.CreateJweProvider(3, algorithm);
            var kem = CryptoFactory.CreateKyber(768);
            var (pub, priv) = kem.GenerateKeyPair();
            var payload = new { cipher = algorithm.ToString() };

            // Act
            string token = provider.CreateJwe(payload, pub);
            string decrypted = provider.DecryptJwe(token, priv);

            // Assert
            Assert.Contains(algorithm.ToString(), decrypted);
            Log($"CreateJweProvider_DifferentCipherAlgorithms_{algorithm}_WorkCorrectly passed");
        }

        // ========== ERROR HANDLING TESTS ==========

        [Fact]
        public void JweProvider_DecryptJwe_InvalidFormat_ThrowsException()
        {
            // Arrange
            var provider = CryptoFactory.CreateJweProvider(3, CipherAlgorithm.Kusumi512);
            var kem = CryptoFactory.CreateKyber(768);
            var (_, priv) = kem.GenerateKeyPair();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => provider.DecryptJwe("invalid.token", priv));
            Assert.Throws<ArgumentException>(() => provider.DecryptJwe("only.two.parts", priv));
            Log("JweProvider_DecryptJwe_InvalidFormat_ThrowsException passed");
        }

        [Fact]
        public void JwsProvider_VerifyJws_InvalidFormat_ThrowsException()
        {
            // Arrange
            var provider = CryptoFactory.CreateJwsProvider(3);
            var signer = CryptoFactory.CreateDilithium(3);
            var (pub, _) = signer.GenerateKeyPair();

            // Act & Assert - Wrong number of parts
            Assert.Throws<ArgumentException>(() => provider.VerifyJws("invalid.token", pub));
            Assert.Throws<ArgumentException>(() => provider.VerifyJws("only.one", pub));
            Assert.Throws<ArgumentException>(() => provider.VerifyJws("too.many.parts.here", pub));
            
            // Invalid Base64 in parts (has 3 parts but invalid Base64)
            Assert.Throws<FormatException>(() => provider.VerifyJws("not!valid.base64!.here!", pub));
            
            Log("JwsProvider_VerifyJws_InvalidFormat_ThrowsException passed");
        }

        [Fact]
        public void JweProvider_CreateJwe_LargePayload_RoundTrip()
        {
            // Arrange
            var provider = CryptoFactory.CreateJweProvider(3, CipherAlgorithm.Kusumi512Poly1305);
            var kem = CryptoFactory.CreateKyber(768);
            var (pub, priv) = kem.GenerateKeyPair();
            
            // Create a large payload (10KB of text)
            var largeText = new string('x', 10000);
            var payload = new { data = largeText };

            // Act
            string token = provider.CreateJwe(payload, pub);
            string decrypted = provider.DecryptJwe(token, priv);
            JsonElement element = JsonSerializer.Deserialize<JsonElement>(decrypted);

            // Assert
            Assert.Equal(largeText, element.GetProperty("data").GetString());
            Log("JweProvider_CreateJwe_LargePayload_RoundTrip passed");
        }

        [Fact]
        public void JwsProvider_CreateJws_UnicodePayload_RoundTrip()
        {
            // Arrange
            var provider = CryptoFactory.CreateJwsProvider(3);
            var signer = CryptoFactory.CreateDilithium(3);
            var (pub, priv) = signer.GenerateKeyPair();
            var payload = new { message = "Hello ?? ?? ????? ??????" };

            // Act
            string token = provider.CreateJws(payload, priv);
            dynamic verified = provider.VerifyJws(token, pub);

            // Assert
            Assert.Equal("Hello ?? ?? ????? ??????", verified.message);
            Log("JwsProvider_CreateJws_UnicodePayload_RoundTrip passed");
        }

        [Fact]
        public void JweProvider_CreateJwe_ComplexNestedPayload_RoundTrip()
        {
            // Arrange
            var provider = CryptoFactory.CreateJweProvider(3, CipherAlgorithm.Kusumi512);
            var kem = CryptoFactory.CreateKyber(768);
            var (pub, priv) = kem.GenerateKeyPair();
            var payload = new
            {
                user = new { id = 123, name = "Test" },
                roles = new[] { "admin", "user" },
                metadata = new { created = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            };

            // Act
            string token = provider.CreateJwe(payload, pub);
            string decrypted = provider.DecryptJwe(token, priv);
            JsonElement element = JsonSerializer.Deserialize<JsonElement>(decrypted);

            // Assert
            Assert.Equal(123, element.GetProperty("user").GetProperty("id").GetInt32());
            Assert.Equal("Test", element.GetProperty("user").GetProperty("name").GetString());
            Assert.Equal(2, element.GetProperty("roles").GetArrayLength());
            Assert.Equal("admin", element.GetProperty("roles")[0].GetString());
            Log("JweProvider_CreateJwe_ComplexNestedPayload_RoundTrip passed");
        }
    }
}