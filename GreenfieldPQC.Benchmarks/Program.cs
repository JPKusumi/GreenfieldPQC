//using System;
//using System.Runtime.InteropServices;

//class Program
//{
//    private const string OqsDll = "oqs";

//    [DllImport(OqsDll)]
//    public static extern int OQS_KEM_alg_count();

//    [DllImport(OqsDll, CharSet = CharSet.Ansi)]
//    public static extern IntPtr OQS_KEM_alg_identifier(int i);

//    [DllImport(OqsDll)]
//    public static extern int OQS_SIG_alg_count();

//    [DllImport(OqsDll, CharSet = CharSet.Ansi)]
//    public static extern IntPtr OQS_SIG_alg_identifier(int i);

//    // Optional: If your liboqs build requires initialization
//    //[DllImport(OqsDll)]
//    //public static extern void OQS_init();

//    static void Main()
//    {
//        try
//        {
//            // Uncomment if your liboqs build requires initialization
//            // OQS_init();

//            Console.WriteLine("Enumerating supported KEM algorithms:");
//            int kemCount = OQS_KEM_alg_count();
//            for (int i = 0; i < kemCount; i++)
//            {
//                string name = Marshal.PtrToStringAnsi(OQS_KEM_alg_identifier(i));
//                Console.WriteLine($"  {name}");
//            }

//            Console.WriteLine("\nEnumerating supported SIG algorithms:");
//            int sigCount = OQS_SIG_alg_count();
//            for (int i = 0; i < sigCount; i++)
//            {
//                string name = Marshal.PtrToStringAnsi(OQS_SIG_alg_identifier(i));
//                Console.WriteLine($"  {name}");
//            }
//        }
//        catch (DllNotFoundException ex)
//        {
//            Console.WriteLine($"Could not load oqs.dll: {ex.Message}");
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine($"Error: {ex}");
//        }
//        Console.ReadLine();
//    }
//}

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
            string first = "No man is an island, entire of itself; every man is a piece of the continent, a part of the main. If a clod be washed away by the sea, Europe is the less, as well as if a promontory were, as well as if a manor of thy friend's or of thine own were: any man's death diminishes me, because I am involved in mankind, and therefore never send to know for whom the bell tolls; it tolls for thee.";
            Console.WriteLine("first length: " + first.Length);
            byte[] second = Encoding.UTF8.GetBytes(first);
            string secondKeySourceString = "0E:22:7B:32:86:79:AA:12:8A:A8:44:C3:D2:5A:79:ED:6D:DE:8C:FA:82:8E:99:7E:F7:56:BD:0B:4E:E4:37:38:70:44:B6:79:97:16:6D:45:04:C5:83:E8:64:B8:A3:3D:D1:A8:E0:83:4A:63:9A:6E:8B:B2:85:68:EE:85:EF:5F";
            string secondKeyReadyString = secondKeySourceString.Replace(":", "");
            byte[] secondKey = Convert.FromHexString(secondKeyReadyString);
            string secondNonceSourceString = "99:27:A4:15:54:1D:83:41:63:A3:46:77";
            string secondNonceReadyString = secondNonceSourceString.Replace(":", "");
            byte[] secondNonce = Convert.FromHexString(secondNonceReadyString);
            var cipher = CryptoFactory.CreateKusumi512(secondKey, secondNonce);
            byte[] third = cipher.EncryptSync(second);
            Console.WriteLine("second length: " + second.Length);
            string fourth = ByteArrayToHexString(third);
            Console.WriteLine("third length: " + third.Length);
            Console.WriteLine("fourth length:" + fourth.Length);
            Console.WriteLine("fourth contents:");
            Console.WriteLine(fourth);
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

