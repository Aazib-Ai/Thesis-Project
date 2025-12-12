"""
Storage Metrics Module for Cloud Overhead Analysis

This module provides utilities to measure ciphertext expansion factors
for the hybrid AES-CKKS encryption system, enabling storage cost analysis
for cloud deployment.

Key Metrics:
- Ciphertext Expansion Factor: encrypted_size / plaintext_size
- AES Overhead: Minimal (~1.1x due to nonce + tag)
- CKKS Overhead: Significant (~100-200x due to polynomial ciphertexts)
- Hybrid Overall: Weighted average based on data distribution

Usage:
    from src.analytics.storage_metrics import calculate_expansion_factor
    
    expansion = calculate_expansion_factor(plaintext_bytes, encrypted_bytes)
    print(f"Expansion factor: {expansion:.2f}x")
"""

import sys
from typing import List
from src.crypto.aes_module import AESCipher
from src.crypto.ckks_module import CKKSContext


def calculate_expansion_factor(plaintext_size: int, encrypted_size: int) -> float:
    """
    Calculate the ciphertext expansion factor.
    
    Args:
        plaintext_size: Size of plaintext data in bytes
        encrypted_size: Size of encrypted data in bytes
        
    Returns:
        Expansion factor (encrypted_size / plaintext_size)
        
    Example:
        >>> plaintext_size = 1000  # 1KB
        >>> encrypted_size = 1100  # 1.1KB (AES with overhead)
        >>> factor = calculate_expansion_factor(plaintext_size, encrypted_size)
        >>> print(f"{factor:.2f}x")
        1.10x
    """
    if plaintext_size == 0:
        return 0.0
    return encrypted_size / plaintext_size


def measure_aes_ciphertext_size(plaintext: str) -> int:
    """
    Measure the size of AES-256-GCM ciphertext in bytes.
    
    AES-GCM overhead includes:
    - Nonce: 12 bytes (base64-encoded → 16 bytes)
    - Ciphertext: len(plaintext) bytes (base64-encoded → ~1.33x)
    - Tag: 16 bytes (base64-encoded → 24 bytes)
    
    Total overhead: ~1.1-1.2x for typical text data
    
    Args:
        plaintext: String to encrypt (will be UTF-8 encoded)
        
    Returns:
        Size of encrypted payload in bytes (JSON serialized)
        
    Example:
        >>> size = measure_aes_ciphertext_size("John Doe")
        >>> print(f"Ciphertext size: {size} bytes")
    """
    key = AESCipher.generate_key()
    plaintext_bytes = plaintext.encode('utf-8')
    encrypted_payload = AESCipher.encrypt(plaintext_bytes, key)
    
    # Calculate total size of the encrypted payload
    # The payload is a dict: {"nonce": str, "ciphertext": str, "tag": str}
    import json
    payload_str = json.dumps(encrypted_payload)
    return len(payload_str.encode('utf-8'))


def measure_ckks_ciphertext_size(values: List[float], ckks_context=None) -> int:
    """
    Measure the size of CKKS ciphertext in bytes.
    
    CKKS ciphertexts are significantly larger than plaintext due to:
    - Polynomial representation (poly_modulus_degree elements)
    - Each coefficient is a large integer (coeff_mod_bit_sizes)
    - Two polynomials per ciphertext (ct0, ct1)
    
    Expected sizes:
    - poly_modulus_degree=8192: ~50-100KB per ciphertext
    - poly_modulus_degree=16384: ~100-200KB per ciphertext
    
    Args:
        values: List of float values to encrypt
        ckks_context: Optional pre-initialized CKKS context (for consistency)
        
    Returns:
        Size of serialized CKKS ciphertext in bytes
        
    Example:
        >>> values = [98.6, 120.0, 80.0]  # Heart rate, systolic, diastolic
        >>> size = measure_ckks_ciphertext_size(values)
        >>> print(f"CKKS ciphertext size: {size / 1024:.2f} KB")
    """
    if ckks_context is None:
        ctx = CKKSContext()
        ctx.create_optimized_context()
    else:
        ctx = ckks_context
    
    # Encrypt the vector
    encrypted_vector = ctx.encrypt_vector(values)
    
    # Serialize to bytes
    serialized = encrypted_vector.serialize()
    
    return len(serialized)


def compare_storage_overhead(num_records: int, 
                             pii_fields: int = 6, 
                             analytics_fields: int = 3,
                             avg_pii_size: int = 50) -> dict:
    """
    Compare storage overhead between pure CKKS and hybrid encryption.
    
    This function models the storage requirements for encrypting patient records
    with different encryption strategies.
    
    Args:
        num_records: Number of patient records
        pii_fields: Number of PII fields per record (encrypted with AES)
        analytics_fields: Number of numeric fields per record (encrypted with CKKS)
        avg_pii_size: Average size of PII field in bytes
        
    Returns:
        Dictionary with storage analysis:
        - plaintext_size: Original data size in bytes
        - pure_ckks_size: Size if all fields encrypted with CKKS
        - hybrid_size: Size with AES (PII) + CKKS (analytics)
        - pure_ckks_expansion: Expansion factor for pure CKKS
        - hybrid_expansion: Expansion factor for hybrid
        - storage_savings: Percentage savings (hybrid vs pure CKKS)
        
    Example:
        >>> analysis = compare_storage_overhead(1000)
        >>> print(f"Hybrid saves {analysis['storage_savings']:.1f}% storage")
    """
    # Calculate plaintext size
    plaintext_per_record = (pii_fields * avg_pii_size) + (analytics_fields * 8)  # 8 bytes per float
    total_plaintext = num_records * plaintext_per_record
    
    # Estimate encrypted sizes
    # AES: ~1.15x expansion (empirical with JSON serialization overhead)
    aes_size_per_field = int(avg_pii_size * 1.15)
    
    # CKKS: Measure actual size for a sample vector
    sample_values = [98.6, 120.0, 80.0]  # Representative analytics values
    ckks_size_per_vector = measure_ckks_ciphertext_size(sample_values)
    
    # Pure CKKS: All fields encrypted with CKKS
    # Each record would need (pii_fields + analytics_fields) separate ciphertexts
    # or batched into vectors (we'll use batched for fairness)
    total_fields = pii_fields + analytics_fields
    pure_ckks_size = num_records * ckks_size_per_vector * (total_fields // 3 + 1)
    
    # Hybrid: AES for PII, CKKS for analytics only
    hybrid_aes_size = num_records * pii_fields * aes_size_per_field
    hybrid_ckks_size = num_records * ckks_size_per_vector
    hybrid_total_size = hybrid_aes_size + hybrid_ckks_size
    
    # Calculate metrics
    pure_ckks_expansion = pure_ckks_size / total_plaintext
    hybrid_expansion = hybrid_total_size / total_plaintext
    storage_savings_pct = ((pure_ckks_size - hybrid_total_size) / pure_ckks_size) * 100
    
    return {
        "plaintext_size": total_plaintext,
        "pure_ckks_size": pure_ckks_size,
        "hybrid_size": hybrid_total_size,
        "pure_ckks_expansion": pure_ckks_expansion,
        "hybrid_expansion": hybrid_expansion,
        "storage_savings_pct": storage_savings_pct,
        "aes_expansion": aes_size_per_field / avg_pii_size,
        "ckks_expansion": ckks_size_per_vector / (analytics_fields * 8)
    }


if __name__ == "__main__":
    # Quick test
    print("Testing Storage Metrics Module")
    print("=" * 50)
    
    # Test AES size
    print("\n1. AES Ciphertext Size:")
    test_plaintext = "John Doe"
    aes_size = measure_aes_ciphertext_size(test_plaintext)
    plaintext_size = len(test_plaintext.encode('utf-8'))
    aes_expansion = calculate_expansion_factor(plaintext_size, aes_size)
    print(f"   Plaintext: {plaintext_size} bytes")
    print(f"   Ciphertext: {aes_size} bytes")
    print(f"   Expansion: {aes_expansion:.2f}x")
    
    # Test CKKS size
    print("\n2. CKKS Ciphertext Size:")
    test_values = [98.6, 120.0, 80.0]
    ckks_size = measure_ckks_ciphertext_size(test_values)
    plaintext_size_ckks = len(test_values) * 8  # 8 bytes per float
    ckks_expansion = calculate_expansion_factor(plaintext_size_ckks, ckks_size)
    print(f"   Plaintext: {plaintext_size_ckks} bytes")
    print(f"   Ciphertext: {ckks_size} bytes ({ckks_size / 1024:.2f} KB)")
    print(f"   Expansion: {ckks_expansion:.2f}x")
    
    # Test storage comparison
    print("\n3. Storage Overhead Comparison (1K records):")
    analysis = compare_storage_overhead(1000)
    print(f"   Plaintext size: {analysis['plaintext_size'] / 1024:.2f} KB")
    print(f"   Pure CKKS: {analysis['pure_ckks_size'] / 1024 / 1024:.2f} MB ({analysis['pure_ckks_expansion']:.1f}x)")
    print(f"   Hybrid: {analysis['hybrid_size'] / 1024 / 1024:.2f} MB ({analysis['hybrid_expansion']:.1f}x)")
    print(f"   Storage savings: {analysis['storage_savings_pct']:.1f}%")
    print("\n" + "=" * 50)
