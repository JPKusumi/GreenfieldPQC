# JWT Provider Test Coverage Analysis (v1.1.0+)

## Executive Summary

**Current Status**: ?? **Adequate but with gaps**

The JWS and JWE providers have **good functional test coverage** for the int-based API but have **significant gaps**:

1. ? Providers are tested via `CreateJwsProvider` and `CreateJweProvider`
2. ? **All existing tests use int-based API** (no enum tests for v1.1.0 functionality)
3. ?? **Factory methods themselves are not directly unit tested** (only tested indirectly)
4. ?? **Constructor behavior is not explicitly tested**
5. ? Core functionality (CreateJws, VerifyJws, CreateJwe, DecryptJwe) is well tested

---

## Constructor Analysis

### JwsProvider Constructor
```csharp
internal class JwsProvider(ISigner signer) : IJwsProvider
{
    private readonly ISigner _signer = signer ?? throw new ArgumentNullException(nameof(signer));
}
```

**Takes**: An `ISigner` instance (e.g., Dilithium)  
**Not directly instantiated by users** - Created via factory method

### JweProvider Constructor
```csharp
public JweProvider(IKeyEncapsulationMechanism kem, CryptoFactory.CipherAlgorithm algorithm)
{
    _kem = kem ?? throw new ArgumentNullException(nameof(kem));
    _algorithm = algorithm;
}
```

**Takes**: 
- An `IKeyEncapsulationMechanism` instance (e.g., Kyber)
- A `CipherAlgorithm` enum

**Not directly instantiated by users** - Created via factory method

---

## Factory Method Implementation

### CreateJwsProvider (int-based)
```csharp
public static IJwsProvider CreateJwsProvider(int dilithiumLevel = 3)
{
    var signer = CreateDilithium(dilithiumLevel);  // Uses INT API
    return new JwsProvider(signer);
}
```

**Instantiates Dilithium with**: `int` parameter  
**Problem**: Even when called with enum, it converts to int and calls `CreateDilithium(int)`

### CreateJwsProvider (enum-based - v1.1.1)
```csharp
public static IJwsProvider CreateJwsProvider(DilithiumSecurityLevel dilithiumLevel = DilithiumSecurityLevel.ML_DSA_65)
{
    return CreateJwsProvider((int)dilithiumLevel);  // Casts to int, calls int overload
}
```

**Flow**: Enum ? Cast to int ? Call int overload ? `CreateDilithium(int)` ? int API all the way down

### CreateJweProvider (int-based)
```csharp
public static IJweProvider CreateJweProvider(int kyberLevel = 3, CipherAlgorithm kusumiAlgorithm = CipherAlgorithm.Kusumi512)
{
    int kyberParam = kyberLevel switch { 1 => 512, 3 => 768, 5 => 1024, ... };
    var kem = CreateKyber(kyberParam);  // Uses INT API
    return new JweProvider(kem, kusumiAlgorithm);
}
```

**Instantiates Kyber with**: `int` parameter  
**Problem**: Maps 1?512, 3?768, 5?1024, then calls `CreateKyber(int)`

### CreateJweProvider (enum-based - v1.1.1)
```csharp
public static IJweProvider CreateJweProvider(KyberSecurityLevel kyberLevel = KyberSecurityLevel.ML_KEM_768, CipherAlgorithm kusumiAlgorithm = CipherAlgorithm.Kusumi512)
{
    return CreateJweProvider((int)kyberLevel, kusumiAlgorithm);  // Casts to int
}
```

**Flow**: Enum ? Cast to int ? Call int overload ? Map to parameter ? `CreateKyber(int)` ? int API

---

## Current Test Coverage

### JWS Provider Tests (all use int API)

| Test | Uses CreateJwsProvider? | API Used | Coverage |
|------|-------------------------|----------|----------|
| `JwsProvider_CreateJws_VerifyJws_RoundTrip` | ? Yes (line 32) | `int` (3) | Basic roundtrip |
| `JwsProvider_VerifyJws_InvalidSignature_ThrowsException` | ? Yes (line 60) | `int` (3) | Security/tampering |
| `JwsProvider_CreateJws_EmptyPayload_RoundTrip` | ? Yes (line 80) | `int` (3) | Edge case |
| `JwsProvider_CreateJws_VariousLevels_RoundTrip` | ? Yes | `int` (2, 3, 5) | All security levels |
| `CreateJwsProvider_WithEnum_CreatesValidProvider` | ? Yes | `enum` | ? **NEW in our changes** |
| `JwsJweNesting_WithEnums_RoundTrip` | ? Yes | `enum` | ? **NEW in our changes** |

### JWE Provider Tests (all use int API)

| Test | Uses CreateJweProvider? | API Used | Coverage |
|------|-------------------------|----------|----------|
| `JweProvider_CreateJwe_VariousLevelsAndVariants_RoundTrip` | ? Yes (line 203) | `int` (1, 3, 5) | All levels + both ciphers |
| `JwsJweNesting_CreateNested_VerifyRoundTrip` | ? Yes (line 232) | `int` (3) | Integration test |
| `CreateJweProvider_WithEnum_CreatesValidProvider` | ? Yes | `enum` | ? **NEW in our changes** |
| `JwsJweNesting_WithEnums_RoundTrip` | ? Yes | `enum` | ? **NEW in our changes** |

### What's NOT Tested

? **Direct factory method testing** - Tests only verify end-to-end behavior, not factory logic  
? **Constructor null argument handling** - No tests for `ArgumentNullException`  
? **Factory method with invalid parameters** - No tests for `ArgumentOutOfRangeException`  
? **JWE cipher algorithm selection logic** - Not explicitly verified  
? **Error handling in CreateJwe/DecryptJwe** for malformed tokens  
? **Edge cases**: empty payloads for JWE, very large payloads, special characters

---

## Critical Finding: Int API Used Throughout

**Discovery**: Even when using enum-based factory methods, the implementation:
1. Casts enum to int immediately
2. Calls the int-based overload
3. Which calls `CreateKyber(int)` or `CreateDilithium(int)`
4. Which uses int-based Parameters constructors

**This means**:
- ? The enum API works correctly (maps to right values)
- ? Both APIs produce identical results
- ? The enum overloads in `CreateKyber`/`CreateDilithium` are **never called by the JWT factories**
- ?? If there were bugs in the enum overloads of `CreateKyber`/`CreateDilithium`, the JWT factories wouldn't expose them

**Example Flow**:
```
User calls: CreateJwsProvider(DilithiumSecurityLevel.ML_DSA_65)
    ?
CreateJwsProvider(enum) casts to int: (int)ML_DSA_65 = 3
    ?
Calls CreateJwsProvider(3)
    ?
Calls CreateDilithium(3)  ? Uses int overload, not enum overload!
    ?
Creates Dilithium with DilithiumParameters(3)  ? Uses int constructor
```

---

## Recommendations

### High Priority - Add Missing Tests

#### 1. Factory Method Unit Tests
```csharp
[Fact]
public void CreateJwsProvider_ReturnsNonNullProvider()
{
    var provider = CryptoFactory.CreateJwsProvider(3);
    Assert.NotNull(provider);
    Assert.IsAssignableFrom<IJwsProvider>(provider);
}

[Theory]
[InlineData(1)]
[InlineData(4)]  // Invalid
[InlineData(10)] // Invalid
public void CreateJwsProvider_InvalidLevel_ThrowsException(int level)
{
    Assert.Throws<ArgumentException>(() => CryptoFactory.CreateJwsProvider(level));
}

[Fact]
public void CreateJweProvider_ReturnsNonNullProvider()
{
    var provider = CryptoFactory.CreateJweProvider(3, CipherAlgorithm.Kusumi512);
    Assert.NotNull(provider);
    Assert.IsAssignableFrom<IJweProvider>(provider);
}
```

#### 2. Constructor Argument Validation Tests
```csharp
[Fact]
public void JwsProvider_Constructor_NullSigner_ThrowsArgumentNullException()
{
    Assert.Throws<ArgumentNullException>(() => new JwsProvider(null));
}

[Fact]
public void JweProvider_Constructor_NullKem_ThrowsArgumentNullException()
{
    Assert.Throws<ArgumentNullException>(() => 
        new JweProvider(null, CipherAlgorithm.Kusumi512));
}
```

#### 3. Error Handling Tests
```csharp
[Fact]
public void JweProvider_DecryptJwe_InvalidFormat_ThrowsException()
{
    var provider = CryptoFactory.CreateJweProvider(3, CipherAlgorithm.Kusumi512);
    Assert.Throws<ArgumentException>(() => 
        provider.DecryptJwe("invalid.token", new byte[2400]));
}

[Fact]
public void JwsProvider_VerifyJws_InvalidFormat_ThrowsException()
{
    var provider = CryptoFactory.CreateJwsProvider(3);
    Assert.Throws<ArgumentException>(() => 
        provider.VerifyJws("invalid.token", new byte[1952]));
}
```

#### 4. Cipher Algorithm Selection Test
```csharp
[Theory]
[InlineData(CipherAlgorithm.Kusumi512)]
[InlineData(CipherAlgorithm.Kusumi512Poly1305)]
public void CreateJweProvider_UsesCorrectCipherAlgorithm(CipherAlgorithm algorithm)
{
    // This would require exposing the algorithm or testing through behavior
    // Currently there's no way to verify which cipher was selected
    var provider = CryptoFactory.CreateJweProvider(3, algorithm);
    
    // Encrypt and decrypt to verify it works with the selected algorithm
    var kem = CryptoFactory.CreateKyber(768);
    var (pub, priv) = kem.GenerateKeyPair();
    string token = provider.CreateJwe(new { test = "cipher" }, pub);
    string decrypted = provider.DecryptJwe(token, priv);
    
    Assert.Contains("cipher", decrypted);
}
```

### Medium Priority - Improve Existing Tests

1. **Add enum API usage to existing integration tests** ? (We did this!)
2. **Test edge cases**: Very large payloads, Unicode characters, nested arrays/objects
3. **Add performance benchmarks** for JWT operations

### Low Priority - Architecture Improvements

1. Consider making factory methods call enum-based `CreateKyber`/`CreateDilithium` overloads directly
2. Add telemetry/logging to track which API path is used
3. Consider adding validation middleware

---

## Conclusion

**Test Coverage Grade: B-**

**Strengths**:
- ? Core functionality well tested
- ? Multiple security levels tested
- ? Integration/roundtrip tests present
- ? Enum API now has basic coverage (from our additions)

**Weaknesses**:
- ? No direct factory method unit tests
- ? No constructor validation tests
- ? No error handling tests
- ? Limited edge case coverage
- ?? Factory methods don't use enum overloads internally (bypasses enum-specific code paths)

**Action Required**: Add the recommended tests above to achieve comprehensive coverage for v1.1.1 release.
