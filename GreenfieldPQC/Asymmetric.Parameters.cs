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

        /// <summary>
        /// Initializes a new instance of the <see cref="KyberParameters"/> class using an enum security level.
        /// </summary>
        /// <param name="securityLevel">The Kyber security level enum.</param>
        public KyberParameters(CryptoFactory.KyberSecurityLevel securityLevel)
        {
            SecurityLevel = securityLevel switch
            {
                CryptoFactory.KyberSecurityLevel.ML_KEM_512 => 512,
                CryptoFactory.KyberSecurityLevel.ML_KEM_768 => 768,
                CryptoFactory.KyberSecurityLevel.ML_KEM_1024 => 1024,
                _ => throw new ArgumentOutOfRangeException(nameof(securityLevel), "Invalid Kyber security level.")
            };
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

        /// <summary>
        /// Initializes a new instance of the <see cref="DilithiumParameters"/> class using an enum security level.
        /// </summary>
        /// <param name="securityLevel">The Dilithium security level enum.</param>
        public DilithiumParameters(CryptoFactory.DilithiumSecurityLevel securityLevel)
        {
            SecurityLevel = securityLevel switch
            {
                CryptoFactory.DilithiumSecurityLevel.ML_DSA_44 => 2,
                CryptoFactory.DilithiumSecurityLevel.ML_DSA_65 => 3,
                CryptoFactory.DilithiumSecurityLevel.ML_DSA_87 => 5,
                _ => throw new ArgumentOutOfRangeException(nameof(securityLevel), "Invalid Dilithium security level.")
            };
        }
    }
}