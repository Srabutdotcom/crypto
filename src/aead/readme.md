In TLS 1.3, the length of the key and initialization vector (IV) depends on the cipher suite in use. TLS 1.3 supports only **Authenticated Encryption with Associated Data (AEAD)** cipher suites. Here's how the lengths are determined:

1. **Key Length**:
   - The key length depends on the selected cipher suite. The most commonly used AEAD algorithms and their key lengths are:
     - **AES-128-GCM**: 128 bits (16 bytes)
     - **AES-256-GCM**: 256 bits (32 bytes)
     - **CHACHA20-POLY1305**: 256 bits (32 bytes)

2. **IV Length**:
   - The IV length is **12 bytes (96 bits)** for all AEAD cipher suites in TLS 1.3. 
   - This is a fixed length defined for all supported AEAD algorithms to ensure consistency.

### Summary Table:
| Cipher Suite               | Key Length | IV Length |
|----------------------------|------------|-----------|
| TLS_AES_128_GCM_SHA256     | 16 bytes   | 12 bytes  |
| TLS_AES_256_GCM_SHA384     | 32 bytes   | 12 bytes  |
| TLS_CHACHA20_POLY1305_SHA256 | 32 bytes  | 12 bytes  |

### Important Notes:
- These lengths are determined by the underlying cryptographic algorithms and are fixed as part of the TLS 1.3 specification.
- The **key material** for these lengths is derived using the TLS 1.3 key schedule with HKDF (HMAC-based Key Derivation Function) as defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).