# Test Fix: JwsProvider_VerifyJws_InvalidFormat_ThrowsException

## Problem
The test was failing with:
```
Assert.Throws() Failure: Exception type was not an exact match
Expected: typeof(System.ArgumentException)
Actual:   typeof(System.FormatException)
```

## Root Cause
The test had this assertion:
```csharp
Assert.Throws<ArgumentException>(() => provider.VerifyJws("only.two.parts", pub));
```

**Issue**: The string `"only.two.parts"` splits into **3 parts** (["only", "two", "parts"]), not 2!

### What Happens in VerifyJws:
1. Line 35: `string[] parts = jwsToken.Split('.');`
2. Line 37: `if (parts.Length != 3) throw new ArgumentException("Invalid JWS format");`
3. Line 41: `byte[] signature = Base64UrlDecode(parts[2]);`

**Flow for "only.two.parts"**:
- ? Splits into 3 parts ? Passes length check
- ? Tries to Base64 decode "parts" ? Throws `FormatException` (not valid Base64)

## Solution
Split the test into two scenarios:

### 1. Wrong Number of Parts ? ArgumentException
```csharp
Assert.Throws<ArgumentException>(() => provider.VerifyJws("invalid.token", pub));      // 2 parts
Assert.Throws<ArgumentException>(() => provider.VerifyJws("only.one", pub));           // 2 parts
Assert.Throws<ArgumentException>(() => provider.VerifyJws("too.many.parts.here", pub)); // 4 parts
```

### 2. Invalid Base64 ? FormatException
```csharp
Assert.Throws<FormatException>(() => provider.VerifyJws("not!valid.base64!.here!", pub));
// Has 3 parts but contains invalid Base64 characters (!)
```

## Status
? **Test now passes** - Properly validates both error scenarios

## Lessons Learned
When testing string splitting:
- Count the dots, not the words!
- `"a.b.c"` has **3 parts**, not 2
- Different validation failures can throw different exception types (ArgumentException vs FormatException)
