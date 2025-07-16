using BenchmarkDotNet.Running;
using System;
using System.Text;
using GreenfieldPQC.Cryptography;

namespace GreenfieldPQC.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine("Hello world, press enter to run the benchmarks.");
            Console.ReadLine();

            // Run the benchmarks
            var summary = BenchmarkRunner.Run<CipherBenchmarks>();

            // Display completion message
            Console.WriteLine("Benchmarking completed. Results saved to BenchmarkDotNet.Artifacts.");
            Console.WriteLine("Press Enter to exit...");
            Console.ReadLine();
        }

        // Make ByteArrayToHexString static to fix CS0120
        static string ByteArrayToHexString(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 3);
            foreach (byte b in bytes)
            {
                if (hex.Length > 0) hex.Append(":");
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString().ToUpper();
        }
        //string ByteArrayToHexString(byte[] bytes)
        //{
        //    StringBuilder hex = new StringBuilder(bytes.Length * 2);
        //    foreach (byte b in bytes)
        //        hex.AppendFormat("{0:x2}", b);
        //    return hex.ToString();
        //}
    }
}
//// See https://aka.ms/new-console-template for more information

