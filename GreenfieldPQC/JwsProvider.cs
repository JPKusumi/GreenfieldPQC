using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Text;
using System.Text.Json;

namespace GreenfieldPQC.Cryptography
{
    internal class JwsProvider(ISigner signer) : IJwsProvider
    {
        private readonly ISigner _signer = signer ?? throw new ArgumentNullException(nameof(signer));  // e.g., Dilithium (ML-DSA)

        public string CreateJws(object payload, byte[] privateKey)
        {
            // Header with alg (ML-DSA)
            var header = new { alg = "ML-DSA-65", typ = "JWT" };  // Adjust level
            string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));

            // Payload
            string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

            // Signing input
            string signingInput = $"{encodedHeader}.{encodedPayload}";
            byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

            // Sign with Dilithium
            byte[] signature = _signer.Sign(signingInputBytes, privateKey);

            // Assemble compact JWS
            string encodedSignature = Base64UrlEncode(signature);
            return $"{encodedHeader}.{encodedPayload}.{encodedSignature}";
        }

        public object VerifyJws(string jwsToken, byte[] publicKey)
        {
            string[] parts = jwsToken.Split('.');
            if (parts.Length != 3) throw new ArgumentException("Invalid JWS format");

            string encodedHeader = parts[0];
            string encodedPayload = parts[1];
            byte[] signature = Base64UrlDecode(parts[2]);

            // Signing input
            string signingInput = $"{encodedHeader}.{encodedPayload}";
            byte[] signingInputBytes = Encoding.UTF8.GetBytes(signingInput);

            // Verify with Dilithium
            bool isValid = _signer.Verify(signingInputBytes, signature, publicKey);
            if (!isValid) throw new InvalidOperationException("Invalid signature");

            // Decode and deserialize payload
            byte[] payloadBytes = Base64UrlDecode(encodedPayload);
            string payloadJson = Encoding.UTF8.GetString(payloadBytes);
            
            // Deserialize to ExpandoObject to support dynamic property access
            var doc = JsonDocument.Parse(payloadJson);
            return JsonElementToExpandoObject(doc.RootElement);
        }

        // Utilities
        private static string Base64UrlEncode(byte[] input) => Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        private static byte[] Base64UrlDecode(string input) => Convert.FromBase64String(input.Replace("-", "+").Replace("_", "/") + new string('=', (4 - input.Length % 4) % 4));
        
        private static ExpandoObject JsonElementToExpandoObject(JsonElement element)
        {
            var expando = new ExpandoObject();
            var dictionary = (IDictionary<string, object>)expando;
            
            foreach (var property in element.EnumerateObject())
            {
                dictionary[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.Object => JsonElementToExpandoObject(property.Value),
                    JsonValueKind.Array => JsonElementToArray(property.Value),
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Number => property.Value.TryGetInt64(out var l) ? l : property.Value.GetDouble(),
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Null => null,
                    _ => property.Value.ToString()
                };
            }
            
            return expando;
        }
        
        private static object[] JsonElementToArray(JsonElement element)
        {
            var list = new List<object>();
            foreach (var item in element.EnumerateArray())
            {
                list.Add(item.ValueKind switch
                {
                    JsonValueKind.Object => JsonElementToExpandoObject(item),
                    JsonValueKind.Array => JsonElementToArray(item),
                    JsonValueKind.String => item.GetString(),
                    JsonValueKind.Number => item.TryGetInt64(out var l) ? l : item.GetDouble(),
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Null => null,
                    _ => item.ToString()
                });
            }
            return list.ToArray();
        }
    }
}