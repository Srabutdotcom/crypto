Yes, in TLS 1.3, the hash function used for key derivation and related processes (e.g., generating secrets and verifying handshake messages) is tied to the **signature algorithm** and the **cipher suite** being used, not directly to the named group. Here's a breakdown:

---

### **How the Hash Function is Determined in TLS 1.3**

1. **Hash Function Options**:
   - TLS 1.3 defines two primary hash functions:
     - **SHA-256**: Produces a 32-byte digest.
     - **SHA-384**: Produces a 48-byte digest.

2. **Named Groups**:
   - Named groups (e.g., `P-256`, `P-384`, `P-512`, `X25519`, `X448`) specify the key exchange mechanism (ECDHE or finite-field Diffie-Hellman).
   - The **named group itself does not determine the hash function**.
   - However, some groups are typically used with specific hash functions for compatibility and performance reasons.

3. **Cipher Suites**:
   - The hash function is determined by the **cipher suite** (e.g., `TLS_AES_128_GCM_SHA256` or `TLS_AES_256_GCM_SHA384`).
   - The last part of the cipher suite (`SHA256` or `SHA384`) specifies the hash function used throughout the handshake.

4. **Signature Algorithms**:
   - The selected signature algorithm during the handshake (e.g., `ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha384`) also influences the hash function, ensuring compatibility between key exchange, certificates, and key derivation.

---

### **Mapping of Named Groups to Hash Functions**

While the hash function is not strictly tied to the named group, the following combinations are common:

| **Named Group**        | **Common Hash Function** | **Reason**                                           |
|-------------------------|--------------------------|-----------------------------------------------------|
| `P-256` (secp256r1)    | SHA-256                 | Matches the key size and efficiency.               |
| `P-384` (secp384r1)    | SHA-384                 | Matches the larger key size.                       |
| `P-521` (secp521r1)    | SHA-384                 | SHA-384 preferred for stronger security guarantees.|
| `X25519`               | SHA-256                 | Optimized for 256-bit security level.              |
| `X448`                 | SHA-384                 | Higher security level; matches well with SHA-384.  |

---

### **Key Takeaways**
1. **The hash function is defined by the cipher suite** used in the handshake.
   - `TLS_AES_128_GCM_SHA256`: Uses **SHA-256**.
   - `TLS_AES_256_GCM_SHA384`: Uses **SHA-384**.

2. **Named groups suggest but do not dictate the hash function**:
   - Most implementations align named groups with compatible hash functions for performance and security.

3. **In your case (e.g., X448)**:
   - You would typically use **SHA-384**, as X448 provides a higher security level than SHA-256.

---