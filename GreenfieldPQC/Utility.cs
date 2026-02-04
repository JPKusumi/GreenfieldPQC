using System;

namespace GreenfieldPQC.Cryptography
{
    public static class Utility
    {
        // Utilities (add to a helper class if not existing)
        public static string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        public static byte[] Base64UrlDecode(string input) => Convert.FromBase64String(input.Replace("-", "+").Replace("_", "/") + new string('=', (4 - input.Length % 4) % 4));
    }
}
