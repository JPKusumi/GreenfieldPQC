using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using GreenfieldPQC.Cryptography;
using System;

[MemoryDiagnoser]
public class KusumiVsThreefishBenchmarks
{
    private Kusumi512 kusumi;
    private Threefish512 threefish;  // ← your class name
    private byte[] data;

    [Params(1 << 10, 1 << 20)]  // 1 KiB and 1 MiB
    public int DataSize { get; set; }

    [Params("Kusumi-AVX512", "Kusumi-AVX2", "Kusumi-Scalar", "Threefish")]
    public string Mode { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var key = new byte[64];
        var nonce = new byte[12];

        kusumi = new Kusumi512(key, nonce);
        threefish = new Threefish512(key, nonce);  // adjust ctor

        data = new byte[DataSize];
        Random.Shared.NextBytes(data);

        // Set forcing flags based on Mode
#if DEBUG || BENCHMARK
        Kusumi512.ForceUseAvx512   = Mode == "Kusumi-AVX512";
        Kusumi512.ForceUseAvx2Only = Mode == "Kusumi-AVX2";
        Kusumi512.ForceScalarOnly  = Mode == "Kusumi-Scalar";
#endif
    }

    [Benchmark(Baseline = true)]
    public void EncryptInPlace()
    {
        var span = data.AsSpan();
        if (Mode.StartsWith("Kusumi"))
        {
            kusumi.EncryptInPlace(span);
        }
        else
        {
            threefish.EncryptInPlace(span);  // adjust method name
        }
    }
}