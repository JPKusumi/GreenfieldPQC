using System;
using System.Buffers.Binary;

namespace GreenfieldPQC.BenchmarkThreefishCompare
{
    /// <summary>
    /// Standalone CTR-mode wrapper for Threefish-512 block cipher — benchmark only.
    /// Does NOT inherit SymmetricCipher; implements a simple CTR loop using core block logic.
    /// </summary>
    public class ThreefishBenchmarkCore
    {
        private const int BlockSizeBytes = 64;
        private const int BlockSizeWords = 8;
        private const int KeySizeWords = BlockSizeWords + 1; // 8 words + parity
        private const int TweakSizeWords = 3;
        private const int Rounds = 72;
        private const ulong C240 = 0x1BD11BDAA9FC1A22UL;

        private readonly ulong[] keySchedule = new ulong[KeySizeWords];
        private readonly ulong[] tweak = new ulong[TweakSizeWords];
        private ulong counter;

        private readonly byte[] keystreamBuffer = new byte[BlockSizeBytes];

        private static readonly int[,] Rotations = new int[8, 4]
        {
            { 46, 36, 19, 37 },
            { 33, 27, 14, 42 },
            { 17, 49, 36, 39 },
            { 44,  9, 54, 56 },
            { 39, 30, 34, 24 },
            { 13, 50, 10, 17 },
            { 25, 29, 39, 43 },
            {  8, 35, 56, 22 }
        };

        private static readonly int[] PermuteTable = { 0, 3, 6, 1, 4, 7, 2, 5 };

        public ThreefishBenchmarkCore(byte[] key, byte[] tweakBytes)
        {
            if (key.Length != 64) throw new ArgumentException("Key must be 64 bytes", nameof(key));
            if (tweakBytes.Length != 16) throw new ArgumentException("Tweak must be 16 bytes", nameof(tweakBytes));

            // Load key (little-endian)
            for (int i = 0; i < BlockSizeWords; i++)
            {
                keySchedule[i] = BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(i * 8));
            }

            // Parity word
            ulong parity = C240;
            for (int i = 0; i < BlockSizeWords; i++)
                parity ^= keySchedule[i];
            keySchedule[BlockSizeWords] = parity;

            // Load tweak
            tweak[0] = BinaryPrimitives.ReadUInt64LittleEndian(tweakBytes.AsSpan(0));
            tweak[1] = BinaryPrimitives.ReadUInt64LittleEndian(tweakBytes.AsSpan(8));
            tweak[2] = tweak[0] ^ tweak[1];

            counter = 0;
        }

        public void EncryptInPlace(Span<byte> inputOutput)
        {
            if (inputOutput.IsEmpty) return;

            int offset = 0;
            while (offset < inputOutput.Length)
            {
                GenerateKeystream(counter, keystreamBuffer);

                int blockLen = Math.Min(BlockSizeBytes, inputOutput.Length - offset);
                for (int i = 0; i < blockLen; i++)
                    inputOutput[offset + i] ^= keystreamBuffer[i];

                offset += blockLen;
                counter++;
            }
        }

        private void GenerateKeystream(ulong ctr, byte[] output)
        {
            ulong[] block = new ulong[BlockSizeWords];
            block[0] = ctr;  // counter in first word
            // remaining words are zero

            EncryptBlock(block);

            for (int i = 0; i < BlockSizeWords; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(i * 8), block[i]);
            }
        }

        private void EncryptBlock(ulong[] block)
        {
            ulong v0 = block[0], v1 = block[1], v2 = block[2], v3 = block[3],
                  v4 = block[4], v5 = block[5], v6 = block[6], v7 = block[7];

            for (int d = 0; d < Rounds; d += 4)
            {
                // Key schedule + tweak injection (once per 4 mini-rounds)
                v0 += keySchedule[d % KeySizeWords];
                v1 += keySchedule[(d + 1) % KeySizeWords];
                v2 += keySchedule[(d + 2) % KeySizeWords];
                v3 += keySchedule[(d + 3) % KeySizeWords];
                v4 += keySchedule[(d + 4) % KeySizeWords];
                v5 += keySchedule[(d + 5) % KeySizeWords] + tweak[d % TweakSizeWords];
                v6 += keySchedule[(d + 6) % KeySizeWords] + tweak[(d + 1) % TweakSizeWords];
                v7 += keySchedule[(d + 7) % KeySizeWords] + (ulong)(d / 4);

                // Mini-round d
                Mix(ref v0, ref v1, Rotations[d % 8, 0]);
                Mix(ref v2, ref v3, Rotations[d % 8, 1]);
                Mix(ref v4, ref v5, Rotations[d % 8, 2]);
                Mix(ref v6, ref v7, Rotations[d % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

                // Mini-round d+1
                Mix(ref v0, ref v1, Rotations[(d + 1) % 8, 0]);
                Mix(ref v2, ref v3, Rotations[(d + 1) % 8, 1]);
                Mix(ref v4, ref v5, Rotations[(d + 1) % 8, 2]);
                Mix(ref v6, ref v7, Rotations[(d + 1) % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

                // Mini-round d+2
                Mix(ref v0, ref v1, Rotations[(d + 2) % 8, 0]);
                Mix(ref v2, ref v3, Rotations[(d + 2) % 8, 1]);
                Mix(ref v4, ref v5, Rotations[(d + 2) % 8, 2]);
                Mix(ref v6, ref v7, Rotations[(d + 2) % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

                // Mini-round d+3
                Mix(ref v0, ref v1, Rotations[(d + 3) % 8, 0]);
                Mix(ref v2, ref v3, Rotations[(d + 3) % 8, 1]);
                Mix(ref v4, ref v5, Rotations[(d + 3) % 8, 2]);
                Mix(ref v6, ref v7, Rotations[(d + 3) % 8, 3]);
                Permute(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
            }

            // Final key/tweak addition after all rounds
            v0 += keySchedule[Rounds % KeySizeWords];
            v1 += keySchedule[(Rounds + 1) % KeySizeWords];
            v2 += keySchedule[(Rounds + 2) % KeySizeWords];
            v3 += keySchedule[(Rounds + 3) % KeySizeWords];
            v4 += keySchedule[(Rounds + 4) % KeySizeWords];
            v5 += keySchedule[(Rounds + 5) % KeySizeWords] + tweak[Rounds % TweakSizeWords];
            v6 += keySchedule[(Rounds + 6) % KeySizeWords] + tweak[(Rounds + 1) % TweakSizeWords];
            v7 += keySchedule[(Rounds + 7) % KeySizeWords] + (ulong)(Rounds / 4);

            // Store back
            block[0] = v0;
            block[1] = v1;
            block[2] = v2;
            block[3] = v3;
            block[4] = v4;
            block[5] = v5;
            block[6] = v6;
            block[7] = v7;
        }

        private static void Mix(ref ulong x, ref ulong y, int r)
        {
            x += y;
            y = RotateLeft(y ^ x, r);
        }

        private static ulong RotateLeft(ulong x, int n)
        {
            return (x << n) | (x >> (64 - n));
        }

        private static void Permute(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3, ref ulong v4, ref ulong v5, ref ulong v6, ref ulong v7)
        {
            ulong temp0 = v0, temp1 = v1, temp2 = v2, temp3 = v3,
                  temp4 = v4, temp5 = v5, temp6 = v6, temp7 = v7;

            v0 = temp0;
            v1 = temp3;
            v2 = temp6;
            v3 = temp1;
            v4 = temp4;
            v5 = temp7;
            v6 = temp2;
            v7 = temp5;
        }
    }
}