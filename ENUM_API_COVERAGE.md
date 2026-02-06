# Enum API Coverage for GreenfieldPQC v1.1.1+

This document outlines all the enum-based API overloads added to support type-safe security level specifications in GreenfieldPQC.

## Enums Defined

### KyberSecurityLevel (CryptoFactory.KyberSecurityLevel)
```csharp
public enum KyberSecurityLevel
{
    ML_KEM_512 = 1,    // NIST Level 1
    ML_KEM_768 = 3,    // NIST Level 3
    ML_KEM_1024 = 5    // NIST Level 5
}
```

### DilithiumSecurityLevel (CryptoFactory.DilithiumSecurityLevel)
```csharp
public enum DilithiumSecurityLevel
{
    ML_DSA_44 = 2,    // NIST Level 2
    ML_DSA_65 = 3,    // NIST Level 3
    ML_DSA_87 = 5     // NIST Level 5
}
```

## API Overloads Added

### 1. CryptoFactory Methods

#### CreateKyber
- **Int overload** (existing): `CreateKyber(int parameter)` - Accepts 512, 768, or 1024
- **Enum overload** (v1.1.0+): `CreateKyber(KyberSecurityLevel level)` - Accepts enum values
- **Usage examples:**
  ```csharp
  var kyber1 = CryptoFactory.CreateKyber(768);  // Old API
  var kyber2 = CryptoFactory.CreateKyber(KyberSecurityLevel.ML_KEM_768);  // New API
  ```

#### CreateDilithium
- **Int overload** (existing): `CreateDilithium(int level)` - Accepts 2, 3, or 5
- **Enum overload** (v1.1.0+): `CreateDilithium(DilithiumSecurityLevel level)` - Accepts enum values
- **Usage examples:**
  ```csharp
  var dilithium1 = CryptoFactory.CreateDilithium(3);  // Old API
  var dilithium2 = CryptoFactory.CreateDilithium(DilithiumSecurityLevel.ML_DSA_65);  // New API
  ```

#### CreateJweProvider
- **Int overload** (existing): `CreateJweProvider(int kyberLevel = 3, CipherAlgorithm kusumiAlgorithm = CipherAlgorithm.Kusumi512)`
- **Enum overload** (v1.1.1+): `CreateJweProvider(KyberSecurityLevel kyberLevel = KyberSecurityLevel.ML_KEM_768, CipherAlgorithm kusumiAlgorithm = CipherAlgorithm.Kusumi512)`
- **Usage examples:**
  ```csharp
  var jwe1 = CryptoFactory.CreateJweProvider(3, CipherAlgorithm.Kusumi512Poly1305);  // Old API
  var jwe2 = CryptoFactory.CreateJweProvider(KyberSecurityLevel.ML_KEM_768, CipherAlgorithm.Kusumi512Poly1305);  // New API
  ```

#### CreateJwsProvider
- **Int overload** (existing): `CreateJwsProvider(int dilithiumLevel = 3)`
- **Enum overload** (v1.1.1+): `CreateJwsProvider(DilithiumSecurityLevel dilithiumLevel = DilithiumSecurityLevel.ML_DSA_65)`
- **Usage examples:**
  ```csharp
  var jws1 = CryptoFactory.CreateJwsProvider(3);  // Old API
  var jws2 = CryptoFactory.CreateJwsProvider(DilithiumSecurityLevel.ML_DSA_65);  // New API
  ```

### 2. Parameter Classes (GreenfieldPQC.Cryptography.Parameters)

#### KyberParameters
- **Int constructor** (existing): `KyberParameters(int securityLevel)` - Accepts 512, 768, or 1024
- **Enum constructor** (v1.1.1+): `KyberParameters(KyberSecurityLevel securityLevel)` - Accepts enum values
- **Usage examples:**
  ```csharp
  var params1 = new KyberParameters(768);  // Old API
  var params2 = new KyberParameters(KyberSecurityLevel.ML_KEM_768);  // New API
  ```

#### DilithiumParameters
- **Int constructor** (existing): `DilithiumParameters(int securityLevel)` - Accepts 2, 3, or 5
- **Enum constructor** (v1.1.1+): `DilithiumParameters(DilithiumSecurityLevel securityLevel)` - Accepts enum values
- **Usage examples:**
  ```csharp
  var params1 = new DilithiumParameters(3);  // Old API
  var params2 = new DilithiumParameters(DilithiumSecurityLevel.ML_DSA_65);  // New API
  ```

## Test Coverage

All enum-based APIs are fully tested with the following test cases:

### Core Factory Tests
- `CreateKyber_WithEnum_ReturnsCorrectAlgorithm` - Tests all 3 Kyber levels
- `CreateDilithium_WithEnum_ReturnsCorrectAlgorithm` - Tests all 3 Dilithium levels
- `CreateJwsProvider_WithEnum_CreatesValidProvider` - Tests JWS creation and verification with enum API
- `CreateJweProvider_WithEnum_CreatesValidProvider` - Tests JWE creation and decryption with enum API

### Integration Tests
- `JwsJweNesting_WithEnums_RoundTrip` - Tests nested JWT scenario using only enum API
- `EnumAndIntAPI_ProduceSameResults` - Tests backward compatibility between int and enum APIs

### Parameter Tests
- `KyberParameters_WithEnum_MapsToCorrectIntValue` - Verifies enum-to-int mapping for Kyber
- `DilithiumParameters_WithEnum_MapsToCorrectIntValue` - Verifies enum-to-int mapping for Dilithium

## Backward Compatibility

? **All existing int-based APIs remain functional and unchanged.**

The enum overloads call the int-based implementations internally, ensuring:
1. No breaking changes for existing code
2. Both APIs can be used interchangeably
3. Cross-compatibility (e.g., create with int API, use with enum API)

## Migration Guide

### Before (v1.0.x)
```csharp
var jweProvider = CryptoFactory.CreateJweProvider(3, CryptoFactory.CipherAlgorithm.Kusumi512Poly1305);
var jwsProvider = CryptoFactory.CreateJwsProvider(3);
var kyber = CryptoFactory.CreateKyber(768);
var dilithium = CryptoFactory.CreateDilithium(3);
```

### After (v1.1.1+) - Type-safe enum API
```csharp
var jweProvider = CryptoFactory.CreateJweProvider(
    KyberSecurityLevel.ML_KEM_768, 
    CryptoFactory.CipherAlgorithm.Kusumi512Poly1305
);
var jwsProvider = CryptoFactory.CreateJwsProvider(DilithiumSecurityLevel.ML_DSA_65);
var kyber = CryptoFactory.CreateKyber(KyberSecurityLevel.ML_KEM_768);
var dilithium = CryptoFactory.CreateDilithium(DilithiumSecurityLevel.ML_DSA_65);
```

## Benefits of Enum API

1. **Type Safety**: Compiler catches invalid security levels at compile time
2. **IntelliSense**: IDE autocomplete shows available security levels
3. **Self-Documenting**: Code clearly shows which NIST standard is being used (ML-KEM-768, ML-DSA-65)
4. **Future-Proof**: Easier to add new security levels without breaking changes
5. **Backward Compatible**: Existing code continues to work without modifications

## Version History

- **v1.1.0**: Added `KyberSecurityLevel` and `DilithiumSecurityLevel` enums; Added enum overloads to `CreateKyber` and `CreateDilithium`
- **v1.1.1**: Added enum overloads to `CreateJweProvider`, `CreateJwsProvider`, `KyberParameters`, and `DilithiumParameters`; Added comprehensive test coverage

## Complete Coverage Status

| Component | Int API | Enum API | Tests |
|-----------|---------|----------|-------|
| CreateKyber | ? | ? | ? |
| CreateDilithium | ? | ? | ? |
| CreateJweProvider | ? | ? | ? |
| CreateJwsProvider | ? | ? | ? |
| KyberParameters | ? | ? | ? |
| DilithiumParameters | ? | ? | ? |
| Kyber constructor | ? (via params) | ? (via params) | ? |
| Dilithium constructor | ? (via params) | ? (via params) | ? |

**Status: ? All enum APIs implemented and tested**
