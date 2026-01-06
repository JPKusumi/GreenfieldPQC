using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using GreenfieldPQC.Cryptography;
using System;

namespace GreenfieldPQC.BenchmarkThreefishCompare
{
    public enum BenchmarkMode
    {
        KusumiAVX512,
        KusumiAVX2,
        KusumiScalar,
        Threefish
    }

    [MemoryDiagnoser]
    [SimpleJob(RuntimeMoniker.Net80, invocationCount: 50, warmupCount: 20, iterationCount: 30)]
    public class KusumiVsThreefishBenchmarks
    {
        private Kusumi512? kusumi;
        private ThreefishBenchmarkCore? threefish;
        private byte[]? data;

        [Params(1 << 20, 1 << 24, 1 << 25, 1 << 26)] // 1 MiB, 16 MiB, 32 MiB, 64 MiB
        public int DataSize { get; set; }

        [ParamsAllValues]
        public BenchmarkMode Mode { get; set; } = BenchmarkMode.KusumiAVX512; // default silences warning

        [GlobalSetup]
        public void Setup()
        {
            var key = new byte[64];
            var nonce = new byte[12];
            var tweak = new byte[16]; // Threefish tweak — zero-filled or copy nonce if desired

            kusumi = new Kusumi512(key, nonce);
            threefish = new ThreefishBenchmarkCore(key, tweak);

            data = new byte[DataSize];
            Random.Shared.NextBytes(data);

#if DEBUG || BENCHMARK
            Kusumi512.BenchmarkForceAvx512 = Mode == BenchmarkMode.KusumiAVX512;
            Kusumi512.BenchmarkForceAvx2   = Mode == BenchmarkMode.KusumiAVX2;
            Kusumi512.BenchmarkForceScalar = Mode == BenchmarkMode.KusumiScalar;
#endif
        }

        [Benchmark]
        public void EncryptInPlace()
        {
            var span = data!.AsSpan(); // ! safe after setup

            if (Mode != BenchmarkMode.Threefish)
            {
                kusumi!.EncryptInPlace(span);
            }
            else
            {
                threefish!.EncryptInPlace(span);
            }
        }

        [IterationCleanup]
        public void Cleanup()
        {
#if DEBUG || BENCHMARK
            Kusumi512.BenchmarkForceAvx512 = false;
            Kusumi512.BenchmarkForceAvx2   = false;
            Kusumi512.BenchmarkForceScalar = false;
#endif
        }
    }
}