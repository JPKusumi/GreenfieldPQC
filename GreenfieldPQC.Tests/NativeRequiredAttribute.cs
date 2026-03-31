using GreenfieldPQC.Cryptography;
using System;
using Xunit;

namespace GreenfieldPQC.Tests
{
    /// <summary>
    /// Marks a fact test as requiring the liboqs native library
    /// (oqs.dll / liboqs.so / liboqs.dylib).
    /// The test is automatically skipped when the native library cannot be loaded,
    /// such as in a CI environment where the native binaries have not yet been built.
    /// </summary>
    public sealed class NativeRequiredFactAttribute : FactAttribute
    {
        public NativeRequiredFactAttribute()
        {
            if (!OqsNativeAvailability.IsAvailable)
                Skip = "Skipped: liboqs native library not available in this environment.";
        }
    }

    /// <summary>
    /// Marks a theory test as requiring the liboqs native library
    /// (oqs.dll / liboqs.so / liboqs.dylib).
    /// The test is automatically skipped when the native library cannot be loaded,
    /// such as in a CI environment where the native binaries have not yet been built.
    /// </summary>
    public sealed class NativeRequiredTheoryAttribute : TheoryAttribute
    {
        public NativeRequiredTheoryAttribute()
        {
            if (!OqsNativeAvailability.IsAvailable)
                Skip = "Skipped: liboqs native library not available in this environment.";
        }
    }

    /// <summary>
    /// Lazily probes whether the liboqs native library can be successfully loaded
    /// in the current process environment.
    /// </summary>
    internal static class OqsNativeAvailability
    {
        private static readonly Lazy<bool> _available = new(Check);

        public static bool IsAvailable => _available.Value;

        private static bool Check()
        {
            try
            {
                // GenerateKeyPair is the first real P/Invoke entry point; a missing native
                // library surfaces here as a DllNotFoundException (possibly wrapped).
                // The result is explicitly discarded; native resources are freed inside
                // Kyber.GenerateKeyPair via a finally block in the interop layer.
                _ = CryptoFactory.CreateKyber(512).GenerateKeyPair();
                return true;
            }
            catch (Exception ex) when (IsNativeLoadFailure(ex))
            {
                return false;
            }
        }

        private static bool IsNativeLoadFailure(Exception ex)
        {
            if (ex is DllNotFoundException or PlatformNotSupportedException)
                return true;
            return ex.InnerException != null && IsNativeLoadFailure(ex.InnerException);
        }
    }
}
