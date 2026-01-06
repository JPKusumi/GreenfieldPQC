```

BenchmarkDotNet v0.15.8, Windows 10 (10.0.19045.6466/22H2/2022Update)
11th Gen Intel Core i9-11900H 2.50GHz, 1 CPU, 16 logical and 8 physical cores
.NET SDK 10.0.101
  [Host]   : .NET 8.0.21 (8.0.21, 8.0.2125.47513), X64 RyuJIT x86-64-v4
  .NET 8.0 : .NET 8.0.21 (8.0.21, 8.0.2125.47513), X64 RyuJIT x86-64-v4

Job=.NET 8.0  Runtime=.NET 8.0  InvocationCount=1  
UnrollFactor=1  

```
| Method         | DataSize | Mode         | Mean       | Error     | StdDev    | Gen0      | Allocated  |
|--------------- |--------- |------------- |-----------:|----------:|----------:|----------:|-----------:|
| **EncryptInPlace** | **1048576**  | **KusumiAVX512** |   **8.915 ms** | **0.1403 ms** | **0.1244 ms** |         **-** |          **-** |
| **EncryptInPlace** | **1048576**  | **KusumiAVX2**   |   **9.424 ms** | **0.1851 ms** | **0.1981 ms** |         **-** |          **-** |
| **EncryptInPlace** | **1048576**  | **KusumiScalar** |   **8.997 ms** | **0.1596 ms** | **0.1493 ms** |         **-** |          **-** |
| **EncryptInPlace** | **1048576**  | **Threefish**    |   **7.027 ms** | **0.1367 ms** | **0.1628 ms** |         **-** |  **1441792 B** |
| **EncryptInPlace** | **16777216** | **KusumiAVX512** | **129.914 ms** | **0.6278 ms** | **0.4901 ms** |         **-** |          **-** |
| **EncryptInPlace** | **16777216** | **KusumiAVX2**   | **129.472 ms** | **2.0018 ms** | **1.6716 ms** |         **-** |          **-** |
| **EncryptInPlace** | **16777216** | **KusumiScalar** | **126.040 ms** | **2.4404 ms** | **2.1633 ms** |         **-** |          **-** |
| **EncryptInPlace** | **16777216** | **Threefish**    | **108.988 ms** | **1.8926 ms** | **1.6777 ms** | **1000.0000** | **23068672 B** |
