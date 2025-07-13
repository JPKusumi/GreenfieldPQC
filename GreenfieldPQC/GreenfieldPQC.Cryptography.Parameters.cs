using System;

namespace GreenfieldPQC.Cryptography.Parameters
{
    /// <summary>
    /// Parameters for Kyber KEM.
    /// </summary>
    public class KyberParameters
    {
        public int SecurityLevel { get; }
        public KyberParameters(int securityLevel)
        {
            if (securityLevel != 512 && securityLevel != 768 && securityLevel != 1024)
                throw new ArgumentException("Invalid security level (512, 768, or 1024).", nameof(securityLevel));
            SecurityLevel = securityLevel;
        }
    }

    /// <summary>
    /// Parameters for Dilithium signatures.
    /// </summary>
    public class DilithiumParameters
    {
        public int SecurityLevel { get; }
        public DilithiumParameters(int securityLevel)
        {
            if (securityLevel != 2 && securityLevel != 3 && securityLevel != 5)
                throw new ArgumentException("Invalid security level (2, 3, or 5).", nameof(securityLevel));
            SecurityLevel = securityLevel;
        }
    }
}