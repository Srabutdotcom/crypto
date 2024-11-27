In **TLS 1.3**, the use of **HKDF** is closely tied to the key schedule and cryptographic processes, as outlined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446). The handling of the **Input Keying Material (IKM)** in TLS 1.3 is structured and follows specific conventions. Here's how the IKM length is handled and standardized for TLS 1.3:

---

### 1. **Role of HKDF in TLS 1.3**
   TLS 1.3 relies on HKDF for deriving cryptographic keys at various stages of the handshake and record encryption. HKDF is used in two primary phases:
   - **HKDF-Extract**: Produces a pseudorandom key (PRK) from IKM and a salt.
   - **HKDF-Expand**: Derives the required output keys from the PRK and a context.

   The process:
   \[
   \text{PRK} = \text{HKDF-Extract}(\text{salt}, \text{IKM})
   \]
   \[
   \text{Output Keys} = \text{HKDF-Expand}(\text{PRK}, \text{info}, \text{length})
   \]

---

### 2. **Length of IKM in TLS 1.3**
   In TLS 1.3, the **IKM** used in the `HKDF-Extract` step is derived from various handshake secrets and Diffie-Hellman outputs. The length of IKM depends on the cryptographic algorithm and handshake phase:

   #### (a) **IKM = Diffie-Hellman Shared Secret**
   - The shared secret (`Z`) is the result of an Elliptic Curve Diffie-Hellman (ECDH) computation.
   - The length of `Z` is determined by the selected key exchange group:
     - **X25519/X448**: 32 or 56 bytes.
     - **P-256, P-384, P-512**: Corresponds to the curve size (e.g., 32, 48, 64 bytes).
   - The shared secret is directly used as the IKM for HKDF-Extract.

   #### (b) **Salt**
   - During `HKDF-Extract`, the **salt** is the previous handshake secret (e.g., `early_secret`, `handshake_secret`, or `master_secret`).
   - If there is no prior secret, the salt is set to a string of zeros with a length equal to the hash output size (e.g., 32 bytes for SHA-256).

   #### (c) **Output Length**
   - The length of the IKM does not need to match the hash function's block size or output size. However, it should provide sufficient entropy for the hash function used in HKDF.
   - For SHA-256, which is commonly used in TLS 1.3:
     - Block size = 64 bytes.
     - Output size = 32 bytes.

---

### 3. **Standardization in TLS 1.3**
   The length of IKM in TLS 1.3 is effectively standardized by the cryptographic parameters negotiated during the handshake:

   - **ECDH Shared Secret (`Z`)**:
     - Length determined by the curve or key exchange algorithm.
     - For example:
       - X25519: Always 32 bytes.
       - P-256: Always 32 bytes.
   - **HKDF Salt**:
     - Derived from the handshake secrets, with a length matching the hash output size.

   The IKM length is flexible but must align with the cryptographic operations and ensure adequate entropy.

---

### 4. **Key Derivation in TLS 1.3**
   TLS 1.3 uses the following key derivation steps with HKDF:

   1. **Early Secret**:
      - IKM = `0x00` (all zeros).
      - Salt = 0 bytes.
   2. **Handshake Secret**:
      - IKM = Shared secret from the key exchange (`Z`).
      - Salt = Early secret.
   3. **Master Secret**:
      - IKM = Handshake secret.
      - Salt = Derived handshake secret.

---

### Example IKM and HKDF Usage in TLS 1.3
If the server selects **X25519** for key exchange:
   - **IKM** = 32 bytes (shared secret `Z` from X25519).
   - **Salt** = Derived from the handshake secret.
   - **HKDF Output** = Pseudorandom key used for further derivation of encryption keys.

---

### Summary
In TLS 1.3, the IKM length is standardized implicitly by:
   - The key exchange algorithm (e.g., X25519, P-256).
   - The cryptographic hash function (e.g., SHA-256).
   - The handshake phase (e.g., early, handshake, or master secrets).

The design ensures compatibility and flexibility while maintaining security based on the negotiated cryptographic parameters.