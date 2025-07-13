using GreenfieldPQC.Cryptography.Parameters;
using GreenfieldPQC.Cryptography.Interop;
using System;
using System.IO;
using System.Runtime.InteropServices;
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

    /// <summary>
    /// Interface for hash functions.
    /// </summary>
    public interface IHash : ICryptoPrimitive
    {
        Task<byte[]> Hash(byte[] input, CancellationToken cancellationToken = default);
        byte[] HashSync(byte[] input);
        Task<byte[]> Hash(Stream input, CancellationToken cancellationToken = default);
        byte[] HashSync(Stream input);
    }

    /// <summary>
    /// SHA-256 hash function wrapper around Microsoft implementation.
    /// </summary>
    public sealed class SHA256 : IHash
    {
        private readonly SHA256Managed _sha256;

        public SHA256()
        {
            _sha256 = new SHA256Managed();
        }

        public string AlgorithmName => "SHA-256";

        public async Task<byte[]> Hash(byte[] input, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return await Task.FromResult(_sha256.ComputeHash(input)).ConfigureAwait(false);
        }

        public byte[] HashSync(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return _sha256.ComputeHash(input);
        }

        public async Task<byte[]> Hash(Stream input, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return await Task.FromResult(_sha256.ComputeHash(input)).ConfigureAwait(false);
        }

        public byte[] HashSync(Stream input)
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
    /// SHA-512 hash function wrapper around Microsoft implementation.
    /// </summary>
    public sealed class SHA512 : IHash
    {
        private readonly SHA512Managed _sha512;

        public SHA512()
        {
            _sha512 = new SHA512Managed();
        }

        public string AlgorithmName => "SHA-512";

        public async Task<byte[]> Hash(byte[] input, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return await Task.FromResult(_sha512.ComputeHash(input)).ConfigureAwait(false);
        }

        public byte[] HashSync(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return _sha512.ComputeHash(input);
        }

        public async Task<byte[]> Hash(Stream input, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return await Task.FromResult(_sha512.ComputeHash(input)).ConfigureAwait(false);
        }

        public byte[] HashSync(Stream input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return _sha512.ComputeHash(input);
        }

        public void Dispose()
        {
            _sha512?.Dispose();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OQS_KEM
    {
        public IntPtr method_name;         // const char*
        public IntPtr alg_version;         // const char*
        public byte claimed_nist_level;    // uint8_t
        [MarshalAs(UnmanagedType.I1)]
        public bool ind_cca;               // bool (C99 _Bool, 1 byte)
        public UIntPtr length_public_key;  // size_t
        public UIntPtr length_secret_key;  // size_t
        public UIntPtr length_ciphertext;  // size_t
        public UIntPtr length_shared_secret; // size_t
        public UIntPtr length_keypair_seed;  // size_t

        // Function pointers (not used in C#)
        public IntPtr keypair_derand;
        public IntPtr keypair;
        public IntPtr encaps;
        public IntPtr decaps;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OQS_SIG
    {
        public IntPtr method_name;         // const char*
        public IntPtr alg_version;         // const char*
        public byte claimed_nist_level;    // uint8_t
        [MarshalAs(UnmanagedType.I1)]
        public bool euf_cma;               // bool
        [MarshalAs(UnmanagedType.I1)]
        public bool suf_cma;               // bool
        [MarshalAs(UnmanagedType.I1)]
        public bool sig_with_ctx_support;  // bool
        public UIntPtr length_public_key;  // size_t
        public UIntPtr length_secret_key;  // size_t
        public UIntPtr length_signature;   // size_t

        // Function pointers (not used in C#)
        public IntPtr keypair;
        public IntPtr sign;
        public IntPtr sign_with_ctx_str;
        public IntPtr verify;
        public IntPtr verify_with_ctx_str;
    }
    public sealed class Kyber : ICryptoPrimitive
    {
        private readonly KyberParameters _parameters;
        private readonly string _algName;

        public Kyber(KyberParameters parameters)
        {
            _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            _algName = $"Kyber{_parameters.SecurityLevel}";
        }

        public string AlgorithmName => $"Kyber-{_parameters.SecurityLevel}";

        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPairSync()
        {
            IntPtr kem = LibOqsInterop.OQS_KEM_new(_algName);
            if (kem == IntPtr.Zero)
                throw new CryptographicException($"Failed to create Kyber KEM for {_algName}.");

            try
            {
                OQS_KEM str = Marshal.PtrToStructure<OQS_KEM>(kem);
                if (!IsValidKemStruct(str))
                    throw new CryptographicException($"Invalid KEM struct returned for {_algName}.");

                byte[] publicKey = new byte[str.length_public_key];
                byte[] privateKey = new byte[str.length_secret_key];
                if (LibOqsInterop.OQS_KEM_keypair(kem, publicKey, privateKey) != 0)
                    throw new CryptographicException("Kyber keypair generation failed.");
                return (publicKey, privateKey);
            }
            finally
            {
                LibOqsInterop.OQS_KEM_free(kem);
            }
        }

        public (byte[] SharedSecret, byte[] Ciphertext) EncapsulateSync(byte[] publicKey)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            IntPtr kem = LibOqsInterop.OQS_KEM_new(_algName);
            if (kem == IntPtr.Zero)
                throw new CryptographicException($"Failed to create Kyber KEM for {_algName}.");

            try
            {
                OQS_KEM str = Marshal.PtrToStructure<OQS_KEM>(kem);
                if (!IsValidKemStruct(str))
                    throw new CryptographicException($"Invalid KEM struct returned for {_algName}.");

                byte[] ciphertext = new byte[str.length_ciphertext];
                byte[] sharedSecret = new byte[str.length_shared_secret];
                if (LibOqsInterop.OQS_KEM_encaps(kem, ciphertext, sharedSecret, publicKey) != 0)
                    throw new CryptographicException("Kyber encapsulation failed.");
                return (sharedSecret, ciphertext);
            }
            finally
            {
                LibOqsInterop.OQS_KEM_free(kem);
            }
        }
        public Task<byte[]> Decapsulate(byte[] ciphertext, byte[] privateKey) => Task.FromResult(DecapsulateSync(ciphertext, privateKey));

        public byte[] DecapsulateSync(byte[] ciphertext, byte[] privateKey)
        {
            if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            IntPtr kem = LibOqsInterop.OQS_KEM_new(_algName);
            if (kem == IntPtr.Zero)
                throw new CryptographicException($"Failed to create Kyber KEM for {_algName}.");

            try
            {
                OQS_KEM str = Marshal.PtrToStructure<OQS_KEM>(kem);
                if (!IsValidKemStruct(str))
                    throw new CryptographicException($"Invalid KEM struct returned for {_algName}.");

                byte[] sharedSecret = new byte[str.length_shared_secret];
                if (LibOqsInterop.OQS_KEM_decaps(kem, sharedSecret, ciphertext, privateKey) != 0)
                    throw new CryptographicException("Kyber decapsulation failed.");
                return sharedSecret;
            }
            finally
            {
                LibOqsInterop.OQS_KEM_free(kem);
            }
        }

        private static bool IsValidKemStruct(OQS_KEM kem)
        {
            // Defensive: check for reasonable sizes (not zero, not absurdly large)
            return kem.length_public_key > 0 && kem.length_public_key < 10000 &&
                   kem.length_secret_key > 0 && kem.length_secret_key < 10000 &&
                   kem.length_ciphertext > 0 && kem.length_ciphertext < 10000 &&
                   kem.length_shared_secret > 0 && kem.length_shared_secret < 10000;
        }

        public void Dispose() { }
    }

    public sealed class Dilithium : ICryptoPrimitive
    {
        private readonly DilithiumParameters _parameters;
        private readonly string _algName;

        public Dilithium(DilithiumParameters parameters)
        {
            _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            _algName = $"Dilithium{_parameters.SecurityLevel}";
        }

        public string AlgorithmName => $"Dilithium-{_parameters.SecurityLevel}";

        public Task<byte[]> Sign(byte[] message, byte[] privateKey) => Task.FromResult(SignSync(message, privateKey));

        public Task<bool> Verify(byte[] message, byte[] signature, byte[] publicKey) => Task.FromResult(VerifySync(message, signature, publicKey));

        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPairSync()
        {
            IntPtr sig = LibOqsInterop.OQS_SIG_new(_algName);
            if (sig == IntPtr.Zero)
                throw new CryptographicException($"Failed to create Dilithium SIG for {_algName}.");

            try
            {
                OQS_SIG str = Marshal.PtrToStructure<OQS_SIG>(sig);
                if (!IsValidSigStruct(str))
                    throw new CryptographicException($"Invalid SIG struct returned for {_algName}.");

                byte[] publicKey = new byte[str.length_public_key];
                byte[] privateKey = new byte[str.length_secret_key];
                if (LibOqsInterop.OQS_SIG_keypair(sig, publicKey, privateKey) != 0)
                    throw new CryptographicException("Dilithium keypair generation failed.");
                return (publicKey, privateKey);
            }
            finally
            {
                LibOqsInterop.OQS_SIG_free(sig);
            }
        }

        public byte[] SignSync(byte[] message, byte[] privateKey)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            IntPtr sig = LibOqsInterop.OQS_SIG_new(_algName);
            if (sig == IntPtr.Zero)
                throw new CryptographicException($"Failed to create Dilithium SIG for {_algName}.");

            try
            {
                OQS_SIG str = Marshal.PtrToStructure<OQS_SIG>(sig);
                if (!IsValidSigStruct(str))
                    throw new CryptographicException($"Invalid SIG struct returned for {_algName}.");

                byte[] signature = new byte[str.length_signature];
                ulong sigLen = str.length_signature;
                if (LibOqsInterop.OQS_SIG_sign(sig, signature, ref sigLen, message, (ulong)message.Length, privateKey) != 0)
                    throw new CryptographicException("Dilithium signing failed.");
                if (sigLen != str.length_signature)
                {
                    Array.Resize(ref signature, (int)sigLen);
                }
                return signature;
            }
            finally
            {
                LibOqsInterop.OQS_SIG_free(sig);
            }
        }

        public bool VerifySync(byte[] message, byte[] signature, byte[] publicKey)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            IntPtr sig = LibOqsInterop.OQS_SIG_new(_algName);
            if (sig == IntPtr.Zero)
                throw new CryptographicException($"Failed to create Dilithium SIG for {_algName}.");

            try
            {
                return LibOqsInterop.OQS_SIG_verify(sig, message, (ulong)message.Length, signature, (ulong)signature.Length, publicKey) == 0;
            }
            finally
            {
                LibOqsInterop.OQS_SIG_free(sig);
            }
        }

        public int GetSignatureLength()
        {
            IntPtr sig = LibOqsInterop.OQS_SIG_new(_algName);
            if (sig == IntPtr.Zero)
                throw new CryptographicException($"Failed to create Dilithium SIG for {_algName}.");

            try
            {
                OQS_SIG str = Marshal.PtrToStructure<OQS_SIG>(sig);
                if (!IsValidSigStruct(str))
                    throw new CryptographicException($"Invalid SIG struct returned for {_algName}.");
                return (int)str.length_signature;
            }
            finally
            {
                LibOqsInterop.OQS_SIG_free(sig);
            }
        }

        private static bool IsValidSigStruct(OQS_SIG sig)
        {
            // Defensive: check for reasonable sizes (not zero, not absurdly large)
            return sig.length_public_key > 0 && sig.length_public_key < 10000 &&
                   sig.length_secret_key > 0 && sig.length_secret_key < 10000 &&
                   sig.length_signature > 0 && sig.length_signature < 10000;
        }

        public void Dispose() { }
    }
}
