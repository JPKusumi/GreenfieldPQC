using GreenfieldPQC.Cryptography;
using System;

namespace GreenfieldPQC.Tests
{
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
