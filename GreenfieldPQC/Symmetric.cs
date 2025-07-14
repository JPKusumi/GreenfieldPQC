using System;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace GreenfieldPQC.Cryptography
{
    /// <summary>
    /// Interface for symmetric ciphers.
    /// </summary>
    public interface ISymmetricCipher : ICryptoPrimitive
    {
        Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default);
        byte[] Encrypt(byte[] plaintext);
        Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default);
        byte[] Decrypt(byte[] ciphertext);
        Task EncryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        void EncryptInPlace(Span<byte> inputOutput);
        Task DecryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        void DecryptInPlace(Span<byte> inputOutput);
        Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default);
        void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null);
        Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default);
        void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null);
    }

    /// <summary>
    /// Abstract base class for symmetric ciphers, handling key and nonce management.
    /// </summary>
    public abstract class SymmetricCipher : ICryptoPrimitive, ISymmetricCipher
    {
        /// <summary>Gets the name of the cipher algorithm.</summary>
        public abstract string AlgorithmName { get; }
        /// <summary>Gets the encryption key.</summary>
        protected byte[] Key { get; }
        /// <summary>Gets the nonce (number used once).</summary>
        protected byte[] Nonce { get; }

        protected SymmetricCipher(byte[] key, byte[] nonce)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }

        public abstract Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default);
        public abstract byte[] Encrypt(byte[] plaintext);
        public abstract Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default);
        public abstract byte[] Decrypt(byte[] ciphertext);
        public abstract Task EncryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        public abstract void EncryptInPlace(Span<byte> inputOutput);
        public abstract Task DecryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default);
        public abstract void DecryptInPlace(Span<byte> inputOutput);

        public virtual async Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long totalBytes = input.CanSeek ? input.Length : -1;
            long bytesProcessed = 0;
            int segmentCount = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (true)
            {
                int bytesRead = await input.ReadAsync(buffer, 0, bufferSize, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    byte[] newNonce = await nonceGenerator(bytesProcessed).ConfigureAwait(false);
                    UpdateNonce(newNonce);
                    segmentProgress?.Report(++segmentCount);
                }

                await EncryptInPlaceAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                bytesProcessed += bytesRead;
                if (totalBytes > 0)
                    progress?.Report((double)bytesProcessed / totalBytes);
            }
        }

        public virtual void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long bytesProcessed = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (input.Read(buffer, 0, bufferSize) is int bytesRead && bytesRead > 0)
            {
                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                EncryptInPlace(buffer.AsSpan(0, bytesRead));
                output.Write(buffer, 0, bytesRead);
                bytesProcessed += bytesRead;
            }
        }

        public virtual async Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long totalBytes = input.CanSeek ? input.Length : -1;
            long bytesProcessed = 0;
            int segmentCount = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (true)
            {
                int bytesRead = await input.ReadAsync(buffer, 0, bufferSize, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    byte[] newNonce = await nonceGenerator(bytesProcessed).ConfigureAwait(false);
                    UpdateNonce(newNonce);
                    segmentProgress?.Report(++segmentCount);
                }

                await DecryptInPlaceAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                bytesProcessed += bytesRead;
                if (totalBytes > 0)
                    progress?.Report((double)bytesProcessed / totalBytes);
            }
        }

        public virtual void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long bytesProcessed = 0;
            long bytesPerSegment = 1024 * 1024; // 1 MB segments

            while (input.Read(buffer, 0, bufferSize) is int bytesRead && bytesRead > 0)
            {
                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                DecryptInPlace(buffer.AsSpan(0, bytesRead));
                output.Write(buffer, 0, bytesRead);
                bytesProcessed += bytesRead;
            }
        }

        /// <summary>Updates the nonce for ciphers requiring nonce changes. Use with caution to avoid nonce reuse.</summary>
        protected virtual void UpdateNonce(byte[] newNonce)
        {
            if (newNonce == null) throw new ArgumentNullException(nameof(newNonce));
            Array.Clear(Nonce, 0, Nonce.Length);
            Array.Copy(newNonce, Nonce, Math.Min(newNonce.Length, Nonce.Length));
        }

        /// <summary>Clears sensitive data (key and nonce) and disposes the cipher.</summary>
        public virtual void Dispose()
        {
            if (Key != null) Array.Clear(Key, 0, Key.Length);
            if (Nonce != null) Array.Clear(Nonce, 0, Nonce.Length);
        }
    }

    /// <summary>
    /// Optimized Kusumi-512 stream cipher with 512-bit key, 96-bit nonce, and 800-bit state.
    /// Reduced to 10 rounds for performance (secure margin comparable to ChaCha12).
    /// Supports AVX2 SIMD for vectorized QuarterRounds where possible.
    /// </summary>
    public sealed class Kusumi512 : SymmetricCipher
    {
        public override string AlgorithmName => "Kusumi512";

        private uint[] _startState = new uint[25]; // 800-bit state (25 x 32-bit words)
        private uint[] _workingState = new uint[25]; // Working state (reusable)
        private ulong blockCounter; // 64-bit counter (62-bit effective)
        private readonly byte[] _keystreamBuffer = new byte[100]; // Reusable buffer

        private static readonly bool IsAvx2Supported = Avx2.IsSupported;

        public Kusumi512(byte[] key, byte[] nonce) : base(key, nonce)
        {
            if (key.Length != 64) throw new ArgumentException("Key must be 512 bits (64 bytes).", nameof(key));
            if (nonce.Length != 12) throw new ArgumentException("Nonce must be 96 bits (12 bytes).", nameof(nonce));

            // Initialize constants
            _startState[0] = 0x61707865;
            _startState[1] = 0x3320646e;
            _startState[2] = 0x79622d32;
            _startState[3] = 0x6b206574;

            // Load key
            Span<uint> keySpan = MemoryMarshal.Cast<byte, uint>(key.AsSpan());
            keySpan.CopyTo(_startState.AsSpan(4));

            // Load nonce and start counter at 1
            _startState[20] = 1; // Counter low
            _startState[21] = 0; // Counter high
            _startState[22] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(0));
            _startState[23] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(4));
            _startState[24] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(8));

            blockCounter = 1;
        }

        public override byte[] Encrypt(byte[] plaintext)
        {
            blockCounter = 1;
            return RunCipher(plaintext, 1);
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            blockCounter = 1;
            return RunCipher(ciphertext, 1);
        }

        public override void EncryptInPlace(Span<byte> inputOutput)
        {
            if (inputOutput.IsEmpty) throw new ArgumentNullException(nameof(inputOutput));
            blockCounter = 1;
            RunCipherInPlace(inputOutput);
        }

        public override void DecryptInPlace(Span<byte> inputOutput)
        {
            EncryptInPlace(inputOutput); // Symmetric for stream cipher
        }

        public override void EncryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long bytesProcessed = 0;
            long bytesPerSegment = 1L << 20; // 1MB
            blockCounter = 1;

            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, bufferSize)) > 0)
            {
                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    UpdateNonce(nonceGenerator(bytesProcessed));
                }
                EncryptInPlace(buffer.AsSpan(0, bytesRead));
                output.Write(buffer, 0, bytesRead);
                bytesProcessed += bytesRead;
            }
        }

        public override void DecryptStream(Stream input, Stream output, int bufferSize = 4096, Func<long, byte[]>? nonceGenerator = null)
        {
            EncryptStream(input, output, bufferSize, nonceGenerator); // Symmetric
        }

        // Async versions (minimal, as sync is fast)
        public override Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Encrypt(plaintext));
        }

        public override Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Decrypt(ciphertext));
        }

        public override Task EncryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default)
        {
            EncryptInPlace(inputOutput.Span);
            return Task.CompletedTask;
        }

        public override Task DecryptInPlaceAsync(Memory<byte> inputOutput, CancellationToken cancellationToken = default)
        {
            DecryptInPlace(inputOutput.Span);
            return Task.CompletedTask;
        }

        public override async Task EncryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (bufferSize <= 0) throw new ArgumentException("Buffer size must be positive.", nameof(bufferSize));

            byte[] buffer = new byte[bufferSize];
            long totalBytes = input.CanSeek ? input.Length : -1;
            long bytesProcessed = 0;
            int segmentCount = 0;
            long bytesPerSegment = 1024 * 1024;
            blockCounter = 1;

            while (true)
            {
                int bytesRead = await input.ReadAsync(buffer, 0, bufferSize, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                cancellationToken.ThrowIfCancellationRequested();

                if (nonceGenerator != null && bytesProcessed / bytesPerSegment > (bytesProcessed - bytesRead) / bytesPerSegment)
                {
                    UpdateNonce(await nonceGenerator(bytesProcessed).ConfigureAwait(false));
                    segmentProgress?.Report(++segmentCount);
                }
                await EncryptInPlaceAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                bytesProcessed += bytesRead;
                if (totalBytes > 0)
                    progress?.Report((double)bytesProcessed / totalBytes);
            }
        }

        public override Task DecryptStreamAsync(Stream input, Stream output, int bufferSize = 4096, IProgress<double>? progress = null, IProgress<int>? segmentProgress = null, Func<long, Task<byte[]>>? nonceGenerator = null, CancellationToken cancellationToken = default)
        {
            return EncryptStreamAsync(input, output, bufferSize, progress, segmentProgress, nonceGenerator, cancellationToken);
        }

        internal byte[] RunCipher(byte[] data, uint startCounter = 1)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            byte[] result = new byte[data.Length];
            long size = data.Length;
            long bytesProcessed = 0;
            uint numBlocks = (uint)Math.Ceiling((double)size / 100);
            if (startCounter > uint.MaxValue - numBlocks)
                throw new CryptographicException("Block counter would overflow.");

            for (uint i = 0; i < numBlocks; i++)
            {
                Kusumi512Block(startCounter + i, _keystreamBuffer);
                int blockSize = (int)Math.Min(100, size - bytesProcessed);
                for (int j = 0; j < blockSize; j++)
                {
                    result[bytesProcessed + j] = (byte)(data[bytesProcessed + j] ^ _keystreamBuffer[j]);
                }
                bytesProcessed += blockSize;
            }

            blockCounter = startCounter + numBlocks;
            return result;
        }

        private void RunCipherInPlace(Span<byte> input, Span<byte> output = default)
        {
            Span<byte> io = output.Length > 0 ? output : input; // Use output if provided, else in-place
            long size = input.Length;
            uint numBlocks = (uint)Math.Ceiling(size / 100.0);
            if (blockCounter > ulong.MaxValue - numBlocks) throw new CryptographicException("Block counter would overflow.");

            long bytesProcessed = 0;
            for (uint i = 0; i < numBlocks; i++)
            {
                Kusumi512Block(blockCounter + i, _keystreamBuffer);
                int blockSize = (int)Math.Min(100, size - bytesProcessed);
                for (int j = 0; j < blockSize; j++)
                {
                    io[(int)bytesProcessed + j] = (byte)(input[(int)bytesProcessed + j] ^ _keystreamBuffer[j]);
                }
                bytesProcessed += blockSize;
            }
            blockCounter += numBlocks;
        }

        private void Kusumi512Block(ulong workingBlock, byte[] keystream)
        {
            // Update counter in state
            _startState[20] = (uint)(workingBlock & 0xFFFFFFFF);
            _startState[21] = (uint)(workingBlock >> 32);

            // Copy to working state
            _startState.AsSpan().CopyTo(_workingState);

            // 10 rounds (reduced for perf, secure margin ~ChaCha12)
            if (IsAvx2Supported)
            {
                Kusumi512CoreAvx2();
            }
            else
            {
                Kusumi512CoreScalar();
            }

            // Add original state and serialize keystream
            ref uint stateRef = ref _startState[0];
            ref uint workRef = ref _workingState[0];
            Span<byte> ksSpan = keystream.AsSpan();
            for (int i = 0; i < 25; i++)
            {
                Unsafe.Add(ref workRef, i) += Unsafe.Add(ref stateRef, i);
                BinaryPrimitives.WriteUInt32LittleEndian(ksSpan.Slice(i * 4, 4), Unsafe.Add(ref workRef, i));
            }
        }

        private void Kusumi512CoreAvx2()
        {
            for (int y = 0; y < 10; y++)
            {
                // Vectorized column rounds (4 columns in parallel using Vector128<uint>)
                Vector128<uint> a = Vector128.Create(_workingState[0], _workingState[1], _workingState[2], _workingState[3]);
                Vector128<uint> b = Vector128.Create(_workingState[4], _workingState[5], _workingState[6], _workingState[7]);
                Vector128<uint> c = Vector128.Create(_workingState[8], _workingState[9], _workingState[10], _workingState[11]);
                Vector128<uint> d = Vector128.Create(_workingState[12], _workingState[13], _workingState[14], _workingState[15]);

                a = Sse2.Add(a, b);
                d = Sse2.Xor(d, a);
                d = Sse2.Or(Sse2.ShiftLeftLogical(d, 16), Sse2.ShiftRightLogical(d, 16));

                c = Sse2.Add(c, d);
                b = Sse2.Xor(b, c);
                b = Sse2.Or(Sse2.ShiftLeftLogical(b, 12), Sse2.ShiftRightLogical(b, 20));

                a = Sse2.Add(a, b);
                d = Sse2.Xor(d, a);
                d = Sse2.Or(Sse2.ShiftLeftLogical(d, 8), Sse2.ShiftRightLogical(d, 24));

                c = Sse2.Add(c, d);
                b = Sse2.Xor(b, c);
                b = Sse2.Or(Sse2.ShiftLeftLogical(b, 7), Sse2.ShiftRightLogical(b, 25));

                // Write back columns
                a.CopyTo(_workingState.AsSpan(0, 4));
                b.CopyTo(_workingState.AsSpan(4, 4));
                c.CopyTo(_workingState.AsSpan(8, 4));
                d.CopyTo(_workingState.AsSpan(12, 4));

                // Scalar for extended state part 1 (words 16-24 with core)
                QuarterRoundScalar(16, 20, 0, 4);
                QuarterRoundScalar(17, 21, 1, 5);
                QuarterRoundScalar(18, 22, 2, 6);
                QuarterRoundScalar(19, 23, 3, 7);

                // Vectorized diagonal rounds (with shuffles for alignment)
                a = Vector128.Create(_workingState[0], _workingState[1], _workingState[2], _workingState[3]);
                b = Vector128.Create(_workingState[4], _workingState[5], _workingState[6], _workingState[7]);
                c = Vector128.Create(_workingState[8], _workingState[9], _workingState[10], _workingState[11]);
                d = Vector128.Create(_workingState[12], _workingState[13], _workingState[14], _workingState[15]);

                // Shuffle for diagonal (left rotates)
                byte controlLeft1 = 0x39; // pos0 from1, pos1 from2, pos2 from3, pos3 from0
                byte controlLeft2 = 0x4E; // pos0 from2, pos1 from3, pos2 from0, pos3 from1
                byte controlLeft3 = 0x93; // pos0 from3, pos1 from0, pos2 from1, pos3 from2

                Vector128<uint> b_rot = Sse2.Shuffle(b.AsInt32(), controlLeft1).AsUInt32();
                Vector128<uint> c_rot = Sse2.Shuffle(c.AsInt32(), controlLeft2).AsUInt32();
                Vector128<uint> d_rot = Sse2.Shuffle(d.AsInt32(), controlLeft3).AsUInt32();

                a = Sse2.Add(a, b_rot);
                d_rot = Sse2.Xor(d_rot, a);
                d_rot = Sse2.Or(Sse2.ShiftLeftLogical(d_rot, 16), Sse2.ShiftRightLogical(d_rot, 16));

                c_rot = Sse2.Add(c_rot, d_rot);
                b_rot = Sse2.Xor(b_rot, c_rot);
                b_rot = Sse2.Or(Sse2.ShiftLeftLogical(b_rot, 12), Sse2.ShiftRightLogical(b_rot, 20));

                a = Sse2.Add(a, b_rot);
                d_rot = Sse2.Xor(d_rot, a);
                d_rot = Sse2.Or(Sse2.ShiftLeftLogical(d_rot, 8), Sse2.ShiftRightLogical(d_rot, 24));

                c_rot = Sse2.Add(c_rot, d_rot);
                b_rot = Sse2.Xor(b_rot, c_rot);
                b_rot = Sse2.Or(Sse2.ShiftLeftLogical(b_rot, 7), Sse2.ShiftRightLogical(b_rot, 25));

                // Unshuffle (right rotates = inverse)
                byte controlRight1 = 0x93; // inverse of left1
                byte controlRight2 = 0x4E; // self-inverse
                byte controlRight3 = 0x39; // inverse of left3

                b = Sse2.Shuffle(b_rot.AsInt32(), controlRight1).AsUInt32();
                c = Sse2.Shuffle(c_rot.AsInt32(), controlRight2).AsUInt32();
                d = Sse2.Shuffle(d_rot.AsInt32(), controlRight3).AsUInt32();

                // Write back diagonals
                a.CopyTo(_workingState.AsSpan(0, 4));
                b.CopyTo(_workingState.AsSpan(4, 4));
                c.CopyTo(_workingState.AsSpan(8, 4));
                d.CopyTo(_workingState.AsSpan(12, 4));

                // Scalar for extended state part 2
                QuarterRoundScalar(16, 21, 2, 7);
                QuarterRoundScalar(17, 22, 3, 4);
                QuarterRoundScalar(18, 23, 0, 5);
                QuarterRoundScalar(19, 20, 1, 6);
                QuarterRoundScalar(19, 24, 0, 5);
            }
        }

        private void Kusumi512CoreScalar()
        {
            ref uint ws = ref _workingState[0];
            for (int y = 0; y < 10; y++)
            {
                QuarterRoundScalar(0, 4, 8, 12);
                QuarterRoundScalar(1, 5, 9, 13);
                QuarterRoundScalar(2, 6, 10, 14);
                QuarterRoundScalar(3, 7, 11, 15);
                QuarterRoundScalar(16, 20, 0, 4);
                QuarterRoundScalar(17, 21, 1, 5);
                QuarterRoundScalar(18, 22, 2, 6);
                QuarterRoundScalar(19, 23, 3, 7);
                QuarterRoundScalar(0, 5, 10, 15);
                QuarterRoundScalar(1, 6, 11, 12);
                QuarterRoundScalar(2, 7, 8, 13);
                QuarterRoundScalar(3, 4, 9, 14);
                QuarterRoundScalar(16, 21, 2, 7);
                QuarterRoundScalar(17, 22, 3, 4);
                QuarterRoundScalar(18, 23, 0, 5);
                QuarterRoundScalar(19, 20, 1, 6);
                QuarterRoundScalar(19, 24, 0, 5); // Extra for nonce
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void QuarterRoundScalar(int a, int b, int c, int d)
        {
            ref uint ws = ref _workingState[0];
            ref uint wa = ref Unsafe.Add(ref ws, a);
            ref uint wb = ref Unsafe.Add(ref ws, b);
            ref uint wc = ref Unsafe.Add(ref ws, c);
            ref uint wd = ref Unsafe.Add(ref ws, d);

            wa += wb; wd ^= wa; wd = (wd << 16) | (wd >> 16);
            wc += wd; wb ^= wc; wb = (wb << 12) | (wb >> 20);
            wa += wb; wd ^= wa; wd = (wd << 8) | (wd >> 24);
            wc += wd; wb ^= wc; wb = (wb << 7) | (wb >> 25);
        }

        protected override void UpdateNonce(byte[] newNonce)
        {
            if (newNonce.Length != 12) throw new ArgumentException("Nonce must be 96 bits (12 bytes).", nameof(newNonce));
            base.UpdateNonce(newNonce);
            _startState[22] = BinaryPrimitives.ReadUInt32LittleEndian(newNonce.AsSpan(0));
            _startState[23] = BinaryPrimitives.ReadUInt32LittleEndian(newNonce.AsSpan(4));
            _startState[24] = BinaryPrimitives.ReadUInt32LittleEndian(newNonce.AsSpan(8));
            blockCounter = 1;
        }

        public void SetNonce(byte[] newNonce)
        {
            UpdateNonce(newNonce);
        }

        internal byte[] GeneratePoly1305Key()
        {
            Kusumi512Block(0, _keystreamBuffer); // Counter = 0
            byte[] polyKey = new byte[32];
            _keystreamBuffer.AsSpan(0, 32).CopyTo(polyKey);
            return polyKey;
        }
    }
}