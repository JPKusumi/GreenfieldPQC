using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.InteropServices;
using System;

namespace GreenfieldPQC.Cryptography
{
    internal static class Kusumi512Avx512Helper
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Kusumi512CoreAvx512(ref uint[] workingState)
        {
            ref uint ws = ref workingState[0];

            // Cast the entire workingState to Span<int> once (zero-copy, safe)
            Span<int> stateAsInt = MemoryMarshal.Cast<uint, int>(workingState.AsSpan());

            for (int y = 0; y < 10; y++)
            {
                // Vectorized column rounds
                Vector512<int> a = Vector512.Create(
                    (int)workingState[0], (int)workingState[1], (int)workingState[2], (int)workingState[3],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                Vector512<int> b = Vector512.Create(
                    (int)workingState[4], (int)workingState[5], (int)workingState[6], (int)workingState[7],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                Vector512<int> c = Vector512.Create(
                    (int)workingState[8], (int)workingState[9], (int)workingState[10], (int)workingState[11],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                Vector512<int> d = Vector512.Create(
                    (int)workingState[12], (int)workingState[13], (int)workingState[14], (int)workingState[15],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

                a = Avx512F.Add(a, b);
                d = Avx512F.Xor(d, a);
                d = Avx512F.Or(Avx512F.ShiftLeftLogical(d, 16), Avx512F.ShiftRightLogical(d, 16));

                c = Avx512F.Add(c, d);
                b = Avx512F.Xor(b, c);
                b = Avx512F.Or(Avx512F.ShiftLeftLogical(b, 12), Avx512F.ShiftRightLogical(b, 20));

                a = Avx512F.Add(a, b);
                d = Avx512F.Xor(d, a);
                d = Avx512F.Or(Avx512F.ShiftLeftLogical(d, 8), Avx512F.ShiftRightLogical(d, 24));

                c = Avx512F.Add(c, d);
                b = Avx512F.Xor(b, c);
                b = Avx512F.Or(Avx512F.ShiftLeftLogical(b, 7), Avx512F.ShiftRightLogical(b, 25));

                // Write back columns — use Span<int> slice
                Vector128<int> tempColA = Avx512F.ExtractVector128(a, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempColA, stateAsInt.Slice(0, 4));

                Vector128<int> tempColB = Avx512F.ExtractVector128(b, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempColB, stateAsInt.Slice(4, 4));

                Vector128<int> tempColC = Avx512F.ExtractVector128(c, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempColC, stateAsInt.Slice(8, 4));

                Vector128<int> tempColD = Avx512F.ExtractVector128(d, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempColD, stateAsInt.Slice(12, 4));

                // Scalar part 1 (unchanged, uses original uint ref)
                QuarterRoundScalar(ref ws, 16, 20, 0, 4);
                QuarterRoundScalar(ref ws, 17, 21, 1, 5);
                QuarterRoundScalar(ref ws, 18, 22, 2, 6);
                QuarterRoundScalar(ref ws, 19, 23, 3, 7);

                // Vectorized diagonal rounds
                a = Vector512.Create(
                    (int)workingState[0], (int)workingState[1], (int)workingState[2], (int)workingState[3],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                b = Vector512.Create(
                    (int)workingState[4], (int)workingState[5], (int)workingState[6], (int)workingState[7],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                c = Vector512.Create(
                    (int)workingState[8], (int)workingState[9], (int)workingState[10], (int)workingState[11],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                d = Vector512.Create(
                    (int)workingState[12], (int)workingState[13], (int)workingState[14], (int)workingState[15],
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

                Vector512<int> controlLeft1 = Vector512.Create(1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                Vector512<int> controlLeft2 = Vector512.Create(2, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                Vector512<int> controlLeft3 = Vector512.Create(3, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

                Vector512<int> b_rot = Avx512F.PermuteVar16x32(b, controlLeft1);
                Vector512<int> c_rot = Avx512F.PermuteVar16x32(c, controlLeft2);
                Vector512<int> d_rot = Avx512F.PermuteVar16x32(d, controlLeft3);

                a = Avx512F.Add(a, b_rot);
                d_rot = Avx512F.Xor(d_rot, a);
                d_rot = Avx512F.Or(Avx512F.ShiftLeftLogical(d_rot, 16), Avx512F.ShiftRightLogical(d_rot, 16));

                c_rot = Avx512F.Add(c_rot, d_rot);
                b_rot = Avx512F.Xor(b_rot, c_rot);
                b_rot = Avx512F.Or(Avx512F.ShiftLeftLogical(b_rot, 12), Avx512F.ShiftRightLogical(b_rot, 20));

                a = Avx512F.Add(a, b_rot);
                d_rot = Avx512F.Xor(d_rot, a);
                d_rot = Avx512F.Or(Avx512F.ShiftLeftLogical(d_rot, 8), Avx512F.ShiftRightLogical(d_rot, 24));

                c_rot = Avx512F.Add(c_rot, d_rot);
                b_rot = Avx512F.Xor(b_rot, c_rot);
                b_rot = Avx512F.Or(Avx512F.ShiftLeftLogical(b_rot, 7), Avx512F.ShiftRightLogical(b_rot, 25));

                Vector512<int> controlRight1 = Vector512.Create(3, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                Vector512<int> controlRight2 = Vector512.Create(2, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                Vector512<int> controlRight3 = Vector512.Create(1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

                b = Avx512F.PermuteVar16x32(b_rot, controlRight1);
                c = Avx512F.PermuteVar16x32(c_rot, controlRight2);
                d = Avx512F.PermuteVar16x32(d_rot, controlRight3);

                // Write back diagonals — same Span<int> slice
                Vector128<int> tempDiagA = Avx512F.ExtractVector128(a, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempDiagA, stateAsInt.Slice(0, 4));

                Vector128<int> tempDiagB = Avx512F.ExtractVector128(b, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempDiagB, stateAsInt.Slice(4, 4));

                Vector128<int> tempDiagC = Avx512F.ExtractVector128(c, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempDiagC, stateAsInt.Slice(8, 4));

                Vector128<int> tempDiagD = Avx512F.ExtractVector128(d, 0);
                System.Runtime.Intrinsics.Vector128.CopyTo(tempDiagD, stateAsInt.Slice(12, 4));

                // Scalar part 2
                QuarterRoundScalar(ref ws, 16, 21, 2, 7);
                QuarterRoundScalar(ref ws, 17, 22, 3, 4);
                QuarterRoundScalar(ref ws, 18, 23, 0, 5);
                QuarterRoundScalar(ref ws, 19, 20, 1, 6);
                QuarterRoundScalar(ref ws, 19, 24, 0, 5);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void QuarterRoundScalar(ref uint ws, int a, int b, int c, int d)
        {
            ref uint wa = ref Unsafe.Add(ref ws, a);
            ref uint wb = ref Unsafe.Add(ref ws, b);
            ref uint wc = ref Unsafe.Add(ref ws, c);
            ref uint wd = ref Unsafe.Add(ref ws, d);

            wa += wb; wd ^= wa; wd = (wd << 16) | (wd >> 16);
            wc += wd; wb ^= wc; wb = (wb << 12) | (wb >> 20);
            wa += wb; wd ^= wa; wd = (wd << 8) | (wd >> 24);
            wc += wd; wb ^= wc; wb = (wb << 7) | (wb >> 25);
        }
    }
}