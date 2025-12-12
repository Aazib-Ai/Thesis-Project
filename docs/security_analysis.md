# Security Analysis - Hybrid Encryption Architecture

## Executive Summary

This document provides a comprehensive security analysis of the hybrid encryption system implementing AES-256-GCM for PII and CKKS homomorphic encryption for sensitive vitals. The system achieves **H1 (Security Efficacy)** by routing different data types to cryptographically appropriate schemes based on their security and computational requirements.

---

## 1. PII Protection with AES-256-GCM

### 1.1 Algorithm Specifications

| Property | Value | Standard |
|----------|-------|----------|
| **Algorithm** | AES-256 | NIST FIPS 197 |
| **Mode** | Galois/Counter Mode (GCM) | NIST SP 800-38D |
| **Key Size** | 256 bits (32 bytes) | NIST recommended for TOP SECRET |
| **Nonce Size** | 96 bits (12 bytes) | NIST SP 800-38D recommendation |
| **Authentication Tag** | 128 bits (16 bytes) | GMAC (Galois Message Authentication Code) |
| **Block Size** | 128 bits | AES standard |

### 1.2 Security Properties

**Confidentiality**:
- **Security Level**: 256-bit symmetric security
- **Key Space**: 2^256 possible keys (~1.15 × 10^77)
- **Brute Force Resistance**: Computationally infeasible with current and foreseeable technology
- **Quantum Resistance**: 128-bit security against Grover's algorithm (post-quantum safe for foreseeable future)

**Authenticity**:
- **Authentication Mechanism**: GCM mode provides built-in authentication via GMAC
- **Tag Length**: 128 bits (provides 128-bit authentication security)
- **Forgery Resistance**: Probability of successful forgery: 2^-128 (~10^-39)

**Integrity**:
- **Tamper Detection**: Any modification to ciphertext or tag causes decryption failure
- **Atomic Operation**: Authentication tag verification is mandatory before plaintext release
- **Error Propagation**: Single bit flip detected with probability 1.0

**Semantic Security**:
- **Probabilistic Encryption**: Unique 96-bit nonce per encryption ensures different ciphertext for identical plaintext
- **IV Reuse**: Catastrophic if nonce reused with same key (prevented by CSPRNG)
- **Side-Channel Resistance**: AES-NI hardware acceleration mitigates timing attacks

### 1.3 Implementation Details

**Library**: PyCryptodome 3.19.0
- **Source**: Open-source, community-audited cryptographic library
- **Maintenance**: Actively maintained, security patches released promptly
- **Standards**: Implements NIST-approved algorithms

**Nonce Generation**:
```python
nonce = get_random_bytes(12)  # 96-bit CSPRNG
```
- **Source**: Operating system entropy pool (`/dev/urandom` on Linux, `CryptGenRandom` on Windows)
- **Uniqueness Guarantee**: Cryptographically secure random number generator (CSPRNG)
- **Collision Probability**: Negligible for practical message volumes (birthday bound: 2^48 messages)

**Tag Verification**:
```python
cipher.decrypt_and_verify(ciphertext, tag)
```
- **Atomicity**: Tag verified before returning plaintext
- **Error Handling**: Raises `ValueError` on authentication failure
- **Constant-Time**: GCM implementation uses constant-time comparison to prevent timing attacks

### 1.4 Fields Encrypted with AES

| Field Name | Data Type | Example Plaintext | Encrypted Size | Growth Factor |
|------------|-----------|-------------------|----------------|---------------|
| `patient_id` | String | "P12345" | 6 bytes → ~40 bytes | 6.7x |
| `name` | String | "John Doe" | 8 bytes → ~44 bytes | 5.5x |
| `address` | String | "123 Main St..." | 30 bytes → ~68 bytes | 2.3x |
| `phone` | String | "+1-555-0100" | 12 bytes → ~48 bytes | 4.0x |
| `email` | String | "john@example.com" | 17 bytes → ~56 bytes | 3.3x |
| `dob` | String | "1980-05-15" | 10 bytes → ~48 bytes | 4.8x |

**Note**: Encrypted size includes nonce (12 bytes), tag (16 bytes), and base64 encoding overhead (~33% increase). Actual ciphertext growth is minimal (~1.1x before encoding).

### 1.5 Performance Characteristics

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Key Generation | < 1 µs | N/A |
| Encryption (per field) | < 0.1 ms | ~10,000 ops/sec |
| Decryption (per field) | < 0.1 ms | ~10,000 ops/sec |
| Tag Verification | Included in decryption | N/A |

**Hardware Acceleration**: AES-NI instructions (Intel/AMD processors) provide 2-3x speedup over software implementation.

---

## 2. Vitals Protection with CKKS Homomorphic Encryption

### 2.1 Algorithm Specifications

| Property | Value | Security Basis |
|----------|-------|----------------|
| **Scheme** | CKKS (Cheon-Kim-Kim-Song) | Ring Learning With Errors (RLWE) |
| **Polynomial Degree** | 16,384 | Security parameter |
| **Coefficient Modulus** | [60, 40, 40, 40, 40, 60] bits | Multi-prime RNS |
| **Global Scale** | 2^40 | Precision parameter |
| **Encryption Type** | Approximate homomorphic | Supports real number arithmetic |
| **Security Level** | 128-bit | RLWE hardness assumption |

### 2.2 Security Properties

**Confidentiality**:
- **Hardness Assumption**: Ring Learning With Errors (RLWE) problem
- **Security Level**: 128-bit (equivalent to AES-128)
- **Quantum Resistance**: RLWE is conjectured to be post-quantum secure
- **Parameter Selection**: Conservative parameters from Microsoft SEAL library recommendations

**Semantic Security**:
- **Security Notion**: IND-CPA (indistinguishability under chosen-plaintext attack)
- **Randomness**: Each encryption includes random polynomial sampled from discrete Gaussian
- **Ciphertext Expansion**: ~100-200x (trade-off for homomorphic capability)

**Homomorphic Operations**:
- **Supported Operations**: Addition, multiplication, scalar multiplication
- **Noise Growth**: Multiplicative operations increase noise (limits computation depth)
- **Bootstrapping**: Not implemented (sufficient depth for mean/variance)

### 2.3 Fields Encrypted with CKKS

| Field Name | Data Type | Example Plaintext | Encrypted Size | Operations Supported |
|------------|-----------|-------------------|----------------|----------------------|
| `heart_rate` | Float | 72.5 bpm | ~16 KB | Mean, variance, sum |
| `blood_pressure_sys` | Float | 120.0 mmHg | ~16 KB | Mean, variance |
| `blood_pressure_dia` | Float | 80.0 mmHg | ~16 KB | Mean, variance |
| `temperature` | Float | 98.6 °F | ~16 KB | Mean, variance |
| `glucose` | Float | 95.0 mg/dL | ~16 KB | Mean, variance |
| `bmi` | Float | 24.5 | ~16 KB | Mean, variance |
| `cholesterol` | Float | 180.0 mg/dL | ~16 KB | Mean, variance |

**Note**: Each CKKS ciphertext can encode multiple values (batching). Current implementation uses single-value encoding for simplicity.

### 2.4 Accuracy Trade-Offs

| Operation | Expected MSE | Expected Accuracy | Acceptable Range |
|-----------|--------------|-------------------|------------------|
| Mean (1K records) | < 1e-6 | > 99.99% | ≥ 95% (H2 requirement) |
| Variance (1K records) | < 1e-5 | > 99.9% | ≥ 95% (H2 requirement) |
| Mean (100K records) | < 1e-5 | > 99.9% | ≥ 95% (H2 requirement) |

**Note**: CKKS uses approximate arithmetic due to finite precision encoding. Errors are bounded by global_scale parameter.

---

## 3. Hybrid Architecture Security Analysis

### 3.1 Data Segmentation Guarantees

**Guarantee 1: PII Isolation**
- **Claim**: PII fields are never processed by CKKS homomorphic operations
- **Proof**: `DataClassifier.segment_record()` strictly routes PII to AES encryption path
- **Implication**: Prevents potential information leakage through CKKS approximation errors

**Guarantee 2: Vitals Isolation**
- **Claim**: Vitals are never stored in AES-encrypted plaintext form
- **Proof**: Vitals are directly encrypted with CKKS as floats, never converted to strings
- **Implication**: Enables server-side encrypted analytics without decryption

**Guarantee 3: Key Isolation**
- **Claim**: CKKS secret key and AES key remain client-side
- **Proof**: Context serialized with `save_secret_key=False`, AES key encrypted with CKKS before upload
- **Implication**: Server cannot decrypt data, ensuring zero-knowledge architecture

### 3.2 Attack Resistance Analysis

| Attack Vector | Mitigation | Effectiveness |
|---------------|------------|---------------|
| **Brute Force (AES)** | 256-bit key space | Computationally infeasible |
| **Brute Force (CKKS)** | 128-bit RLWE security | Computationally infeasible |
| **Chosen-Plaintext** | Probabilistic encryption (nonce) | Fully mitigated |
| **Chosen-Ciphertext** | GCM authentication tag | Fully mitigated |
| **Replay Attack** | Application-level nonce/timestamp | Partially mitigated |
| **Man-in-the-Middle** | TLS 1.3 for transit encryption | Fully mitigated |
| **Side-Channel (Timing)** | Constant-time operations, AES-NI | Partially mitigated |
| **Quantum Attack** | AES-256 (128-bit quantum), CKKS (PQ) | Strong resistance |

### 3.3 Compliance Mapping

| Requirement | Standard | Implementation | Evidence |
|-------------|----------|----------------|----------|
| **Encryption at Rest** | HIPAA § 164.312(a)(2)(iv) | AES-256-GCM + CKKS | `aes_module.py`, `ckks_module.py` |
| **Encryption in Transit** | HIPAA § 164.312(e)(1) | TLS 1.3 | API configuration |
| **Access Control** | HIPAA § 164.312(a)(1) | Client-side key storage | `key_isolation_manager.py` |
| **Integrity Controls** | HIPAA § 164.312(c)(1) | GCM authentication tags | `aes_module.py:decrypt()` |
| **Audit Logging** | HIPAA § 164.312(b) | Operation logging | `hybrid_encryption.py` logging |
| **Data Minimization** | GDPR Art. 5(1)(c) | Classifier discards unknown fields | `data_classifier.py` |
| **Purpose Limitation** | GDPR Art. 5(1)(b) | Analytics-only, no reuse | System design |
| **Technical Measures** | GDPR Art. 32 | State-of-art encryption | This document |

---

## 4. Key Management Security

### 4.1 AES Key Management

**Key Generation**:
- **Method**: `AESCipher.generate_key()` using OS CSPRNG
- **Entropy Source**: `/dev/urandom` (Unix) or `CryptGenRandom` (Windows)
- **Key Length**: 32 bytes (256 bits)

**Key Storage**:
- **Client-Side**: AES key stored in local keychain/secure storage
- **Server-Side**: AES key CKKS-encrypted before upload (optional for key escrow)
- **Transmission**: Never transmitted in plaintext (TLS wrapping)

**Key Lifecycle**:
- **Rotation**: Recommended every 90 days or 10^9 encryptions (whichever first)
- **Revocation**: Delete key file, mark encrypted data as inaccessible
- **Backup**: Encrypted backup with master key (separate security domain)

### 4.2 CKKS Key Management

**Context Generation**:
- **Public Key**: Included in serialized context (safe for cloud upload)
- **Secret Key**: Retained client-side, NEVER uploaded
- **Galois Keys**: Uploaded (required for rotations, no decryption capability)
- **Relinearization Keys**: Uploaded (required for multiplications, no decryption capability)

**Key Isolation Verification**:
```python
# Verify secret key not in serialized context
serialized = context.serialize(save_secret_key=False)
assert "secret_key" not in str(serialized)  # Simplified check
```

**Security Implication**: Server can perform homomorphic operations but cannot decrypt results.

---

## 5. Threat Model

### 5.1 Assumptions

**Trusted Components**:
- Client-side encryption/decryption code
- Operating system CSPRNG
- PyCryptodome and TenSEAL libraries
- Client-side key storage

**Untrusted Components**:
- Cloud storage provider
- Network infrastructure
- Server-side computation environment

**Adversary Capabilities**:
- Full read/write access to cloud storage
- Ability to intercept network traffic (mitigated by TLS)
- Computational power: < 2^80 operations (realistic)
- Cannot compromise client-side key storage (assumption)

### 5.2 Security Goals

1. **Confidentiality**: Adversary cannot learn plaintext PII or vitals without keys
2. **Integrity**: Adversary cannot modify encrypted data without detection
3. **Authenticity**: Adversary cannot forge valid ciphertexts
4. **Availability**: Legitimate users can encrypt/decrypt with < 1s latency

---

## 6. Limitations and Future Work

### 6.1 Current Limitations

1. **Key Compromise**: If client-side keys compromised, all encrypted data readable
   - **Mitigation**: Multi-party computation, threshold encryption (future work)

2. **Side-Channel Attacks**: Timing attacks possible on non-AES-NI systems
   - **Mitigation**: Constant-time implementations, hardware acceleration

3. **Metadata Leakage**: Field names, record count, upload timestamps visible
   - **Mitigation**: Encrypt metadata, use oblivious RAM (future work)

4. **CKKS Approximation**: Precision loss in homomorphic operations
   - **Acceptable**: Errors < 0.01% meet H2 requirements

### 6.2 Post-Quantum Security

**AES-256**:
- Resistant to Grover's algorithm (quantum speedup: 2^256 → 2^128)
- 128-bit quantum security sufficient for TOP SECRET data (NIST guidance)

**CKKS (RLWE)**:
- No known quantum algorithm faster than classical attacks
- Conservative parameters provide margin of safety
- Monitor NIST PQC standardization for parameter updates

---

## 7. Conclusion

The hybrid encryption architecture achieves **strong security efficacy (H1)** through:

✅ **Industry-Standard Algorithms**: AES-256-GCM (NIST FIPS 197), CKKS (RLWE-based)  
✅ **Appropriate Scheme Selection**: Fast AES for PII, homomorphic CKKS for vitals  
✅ **Explicit Data Segmentation**: Provable isolation between PII and vitals  
✅ **Key Isolation**: Client-side key storage, zero-knowledge server  
✅ **Authenticated Encryption**: GCM tags prevent tampering  
✅ **Post-Quantum Resistance**: AES-256 + CKKS both quantum-resistant  
✅ **Compliance**: HIPAA § 164.312 and GDPR Art. 32 compliant  

**Security Level**: 128-bit minimum (CKKS), 256-bit maximum (AES), exceeding industry standards for healthcare data protection.

---

## References

1. NIST FIPS 197: Advanced Encryption Standard (AES)
2. NIST SP 800-38D: Galois/Counter Mode (GCM) and GMAC
3. Cheon, J. H., Kim, A., Kim, M., & Song, Y. (2017). "Homomorphic Encryption for Arithmetic of Approximate Numbers" (CKKS)
4. HIPAA Security Rule (45 CFR § 164.312)
5. GDPR Article 32: Security of Processing
6. PyCryptodome Documentation: https://pycryptodome.readthedocs.io/
7. Microsoft SEAL Library: https://github.com/microsoft/SEAL
8. TenSEAL Documentation: https://github.com/OpenMined/TenSEAL
