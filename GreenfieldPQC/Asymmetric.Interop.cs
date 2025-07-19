using System;
using System.Runtime.InteropServices;

namespace GreenfieldPQC.Cryptography.Interop
{
    /// <summary>
    /// P/Invoke bindings for liboqs (Open Quantum Safe library). 
    /// </summary>
    internal static class LibOqsInterop
    {
        private const string LibName = "oqs"; // Matches oqs.dll

        [DllImport(LibName, CharSet = CharSet.Ansi)]
        public static extern IntPtr OQS_KEM_new([MarshalAs(UnmanagedType.LPStr)] string algorithm_name);

        [DllImport(LibName)]
        public static extern void OQS_KEM_free(IntPtr kem);

        [DllImport(LibName)]
        public static extern int OQS_KEM_keypair(IntPtr kem, [Out] byte[] public_key, [Out] byte[] secret_key);

        [DllImport(LibName)]
        public static extern int OQS_KEM_encaps(IntPtr kem, [Out] byte[] ciphertext, [Out] byte[] shared_secret, [In] byte[] public_key);

        [DllImport(LibName)]
        public static extern int OQS_KEM_decaps(IntPtr kem, [Out] byte[] shared_secret, [In] byte[] ciphertext, [In] byte[] secret_key);

        [DllImport(LibName, CharSet = CharSet.Ansi)]
        public static extern IntPtr OQS_SIG_new([MarshalAs(UnmanagedType.LPStr)] string algorithm_name);

        [DllImport(LibName)]
        public static extern void OQS_SIG_free(IntPtr sig);

        [DllImport(LibName)]
        public static extern int OQS_SIG_keypair(IntPtr sig, [Out] byte[] public_key, [Out] byte[] secret_key);

        [DllImport(LibName)]
        public static extern int OQS_SIG_sign(IntPtr sig, [Out] byte[] signature, ref ulong sig_len, [In] byte[] message, ulong message_len, [In] byte[] secret_key);

        [DllImport(LibName)]
        public static extern int OQS_SIG_verify(IntPtr sig, [In] byte[] message, ulong message_len, [In] byte[] signature, ulong sig_len, [In] byte[] public_key);
    }
}