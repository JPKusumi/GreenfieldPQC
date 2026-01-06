using BenchmarkDotNet.Running;
using GreenfieldPQC.BenchmarkThreefishCompare;

namespace GreenfieldPQC.BenchmarkThreefishCompare
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkRunner.Run<KusumiVsThreefishBenchmarks>();
        }
    }
}