using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace GreenfieldPQC.Cryptography.Interop
{
    /// <summary>
    /// P/Invoke bindings for liboqs (Open Quantum Safe library). 
    /// </summary>
    internal static class LibOqsInterop
    {
        private const string LibName = "oqs"; // Matches oqs.dll on Windows; resolver maps to liboqs.so/.dylib on Linux/macOS

        static LibOqsInterop()
        {
            NativeLibrary.SetDllImportResolver(typeof(LibOqsInterop).Assembly, ResolveOqs);
        }

        /// <summary>
        /// Resolves the liboqs native library path deterministically for Linux and macOS.
        /// Searches the app base directory and the <c>runtimes/&lt;rid&gt;/native/</c> subdirectory
        /// so the bundled library (from the NuGet package) is always preferred over any system-installed
        /// stub. Falls back to default .NET resolution on Windows or when the explicit paths are absent.
        /// </summary>
        private static IntPtr ResolveOqs(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (libraryName != LibName)
                return IntPtr.Zero;

            // win-arm64 is not a supported platform (see README). Throw a clear error rather than
            // letting default .NET resolution produce an opaque DllNotFoundException.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                RuntimeInformation.OSArchitecture == Architecture.Arm64)
            {
                throw new PlatformNotSupportedException(
                    "GreenfieldPQC does not support win-arm64. " +
                    "Supported platforms are win-x64, linux-x64, linux-arm64, osx-x64, and osx-arm64.");
            }

            // On Windows (x64) the default resolution finds oqs.dll without any special handling.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return IntPtr.Zero;

            string nativeLibName = RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? "liboqs.dylib"
                : "liboqs.so";

            string rid = GetRuntimeIdentifier();
            string? assemblyDir = Path.GetDirectoryName(assembly.Location);

            // Probe in priority order so the bundled NuGet library wins over system libraries.
            string?[] candidates =
            [
                // 1. Flat output / app-base directory (handles CopyToOutputDirectory without TargetPath)
                Path.Combine(AppContext.BaseDirectory, nativeLibName),
                // 2. runtimes/<rid>/native/ relative to the app base (NuGet publish layout)
                Path.Combine(AppContext.BaseDirectory, "runtimes", rid, "native", nativeLibName),
                // 3. Same two paths relative to the executing assembly location
                assemblyDir != null ? Path.Combine(assemblyDir, nativeLibName) : null,
                assemblyDir != null ? Path.Combine(assemblyDir, "runtimes", rid, "native", nativeLibName) : null,
            ];

            foreach (string? candidate in candidates)
            {
                if (candidate != null && File.Exists(candidate) &&
                    NativeLibrary.TryLoad(candidate, out IntPtr handle))
                {
                    return handle;
                }
            }

            // Fall back to default .NET resolution (e.g., LD_LIBRARY_PATH, DYLD_LIBRARY_PATH).
            if (NativeLibrary.TryLoad(nativeLibName, assembly, searchPath, out IntPtr defaultHandle))
                return defaultHandle;

            throw new DllNotFoundException(
                $"Could not load native library '{nativeLibName}' (RID: {rid}). " +
                $"Ensure the GreenfieldPQC NuGet package is correctly installed and the native library " +
                $"exists in the 'runtimes/{rid}/native/' directory relative to the application.");
        }

        private static string GetRuntimeIdentifier()
        {
            string os = RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" : "linux";
            string arch = RuntimeInformation.OSArchitecture switch
            {
                Architecture.X64 => "x64",
                Architecture.Arm64 => "arm64",
                _ => throw new PlatformNotSupportedException(
                    $"Unsupported architecture '{RuntimeInformation.OSArchitecture}' for liboqs native library resolution. " +
                    $"Supported architectures are x64 and arm64.")
            };
            return $"{os}-{arch}";
        }

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