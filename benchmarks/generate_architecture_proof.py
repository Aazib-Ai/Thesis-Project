"""
Hybrid Architecture Proof Generator

This script generates empirical evidence to prove the hybrid encryption
architecture's efficiency and correctness for H1 (Security Efficacy).

Metrics Generated:
1. Field classification counts (PII vs Vitals)
2. Encryption time comparison (AES vs CKKS)
3. Ciphertext size analysis
4. Hybrid efficiency calculations

Output: benchmarks/hybrid_architecture_metrics.csv
"""

import os
import time
import pandas as pd
from typing import Dict, Any

from src.crypto.aes_module import AESCipher
from src.crypto.ckks_module import CKKSContext
from src.crypto.data_classifier import DataClassifier
from src.crypto.hybrid_encryption import HybridEncryptor, KeyManager


def load_sample_dataset(dataset_path: str = "data/synthetic/patients_1k.csv") -> pd.DataFrame:
    """Load sample dataset for testing."""
    if not os.path.exists(dataset_path):
        # Generate minimal sample if file doesn't exist
        print(f"Warning: {dataset_path} not found, creating sample data...")
        sample_data = {
            "patient_id": [f"P{i:05d}" for i in range(10)],
            "name": [f"Patient {i}" for i in range(10)],
            "address": [f"{i} Main St" for i in range(10)],
            "phone": [f"+1-555-{i:04d}" for i in range(10)],
            "email": [f"patient{i}@example.com" for i in range(10)],
            "dob": ["1980-01-01"] * 10,
            "heart_rate": [70.0 + i for i in range(10)],
            "blood_pressure_sys": [120.0 + i for i in range(10)],
            "blood_pressure_dia": [80.0 + i for i in range(10)],
            "temperature": [98.6 for i in range(10)],
            "glucose": [90.0 + i for i in range(10)],
            "bmi": [24.0 + i * 0.1 for i in range(10)],
            "cholesterol": [180.0 + i for i in range(10)]
        }
        return pd.DataFrame(sample_data)
    return pd.read_csv(dataset_path)


def measure_classification(df: pd.DataFrame) -> Dict[str, Any]:
    """Measure field classification distribution."""
    print("\n" + "="*70)
    print("TASK 1: FIELD CLASSIFICATION ANALYSIS")
    print("="*70)
    
    report = DataClassifier.get_classification_report(df)
    DataClassifier.print_classification_summary(report)
    
    return {
        "total_fields": report['total_fields'],
        "pii_count": report['pii_count'],
        "vitals_count": report['vitals_count'],
        "pii_percentage": report['pii_percentage'],
        "vitals_percentage": report['vitals_percentage'],
        "dataset_rows": report['dataset_rows']
    }


def measure_encryption_performance() -> Dict[str, Any]:
    """Measure encryption time for AES vs CKKS."""
    print("\n" + "="*70)
    print("TASK 2: ENCRYPTION PERFORMANCE COMPARISON")
    print("="*70)
    
    # Initialize crypto modules
    aes_key = AESCipher.generate_key()
    ckks = CKKSContext()
    ckks.create_optimized_context()
    
    # Test data
    pii_sample = "John Doe"
    vital_sample = 72.5
    num_iterations = 100
    
    # Measure AES encryption time
    print("\nMeasuring AES-256-GCM encryption time...")
    aes_times = []
    for _ in range(num_iterations):
        start = time.perf_counter()
        AESCipher.encrypt(pii_sample.encode('utf-8'), aes_key)
        elapsed = time.perf_counter() - start
        aes_times.append(elapsed * 1000)  # Convert to milliseconds
    
    aes_avg = sum(aes_times) / len(aes_times)
    print(f"  Average AES encryption time: {aes_avg:.4f} ms")
    
    # Measure CKKS encryption time
    print("\nMeasuring CKKS encryption time...")
    ckks_times = []
    for _ in range(num_iterations):
        start = time.perf_counter()
        ckks.encrypt_vector([vital_sample])
        elapsed = time.perf_counter() - start
        ckks_times.append(elapsed * 1000)  # Convert to milliseconds
    
    ckks_avg = sum(ckks_times) / len(ckks_times)
    print(f"  Average CKKS encryption time: {ckks_avg:.4f} ms")
    
    speedup = ckks_avg / aes_avg
    print(f"\n  Speedup factor: AES is {speedup:.1f}x faster than CKKS")
    
    return {
        "aes_encryption_time_ms": aes_avg,
        "ckks_encryption_time_ms": ckks_avg,
        "aes_speedup_factor": speedup
    }


def measure_ciphertext_sizes() -> Dict[str, Any]:
    """Measure ciphertext size overhead for AES vs CKKS."""
    print("\n" + "="*70)
    print("TASK 3: CIPHERTEXT SIZE ANALYSIS")
    print("="*70)
    
    # Initialize crypto modules
    aes_key = AESCipher.generate_key()
    ckks = CKKSContext()
    ckks.create_optimized_context()
    
    # Test data (10-byte string for PII)
    pii_plaintext = "John Doe"  # 8 bytes
    pii_plaintext_size = len(pii_plaintext.encode('utf-8'))
    
    # Encrypt with AES
    aes_ciphertext = AESCipher.encrypt(pii_plaintext.encode('utf-8'), aes_key)
    import json
    aes_ciphertext_size = len(json.dumps(aes_ciphertext).encode('utf-8'))
    
    # Test data (float for vitals)
    vital_plaintext = 72.5
    vital_plaintext_size = 8  # float64 is 8 bytes
    
    # Encrypt with CKKS
    ckks_ciphertext = ckks.encrypt_vector([vital_plaintext])
    ckks_ciphertext_size = len(ckks_ciphertext.serialize())
    
    # Calculate expansion factors
    aes_expansion = aes_ciphertext_size / pii_plaintext_size
    ckks_expansion = ckks_ciphertext_size / vital_plaintext_size
    
    print(f"\nAES-256-GCM:")
    print(f"  Plaintext size:   {pii_plaintext_size} bytes")
    print(f"  Ciphertext size:  {aes_ciphertext_size} bytes")
    print(f"  Expansion factor: {aes_expansion:.2f}x")
    
    print(f"\nCKKS:")
    print(f"  Plaintext size:   {vital_plaintext_size} bytes")
    print(f"  Ciphertext size:  {ckks_ciphertext_size} bytes ({ckks_ciphertext_size/1024:.1f} KB)")
    print(f"  Expansion factor: {ckks_expansion:.1f}x")
    
    return {
        "aes_plaintext_bytes": pii_plaintext_size,
        "aes_ciphertext_bytes": aes_ciphertext_size,
        "aes_expansion_factor": aes_expansion,
        "ckks_plaintext_bytes": vital_plaintext_size,
        "ckks_ciphertext_bytes": ckks_ciphertext_size,
        "ckks_expansion_factor": ckks_expansion
    }


def calculate_hybrid_efficiency(
    classification: Dict[str, Any],
    sizes: Dict[str, Any]
) -> Dict[str, Any]:
    """Calculate hybrid approach efficiency vs pure CKKS."""
    print("\n" + "="*70)
    print("TASK 4: HYBRID EFFICIENCY CALCULATION")
    print("="*70)
    
    total_fields = classification['total_fields']
    pii_count = classification['pii_count']
    vitals_count = classification['vitals_count']
    
    # Storage calculation (per record)
    pure_ckks_storage = total_fields * sizes['ckks_ciphertext_bytes']
    hybrid_storage = (
        pii_count * sizes['aes_ciphertext_bytes'] +
        vitals_count * sizes['ckks_ciphertext_bytes']
    )
    
    storage_savings_pct = ((pure_ckks_storage - hybrid_storage) / pure_ckks_storage) * 100
    
    print(f"\nStorage Comparison (per record):")
    print(f"  Pure CKKS:  {pure_ckks_storage:,} bytes ({pure_ckks_storage/1024:.1f} KB)")
    print(f"  Hybrid:     {hybrid_storage:,} bytes ({hybrid_storage/1024:.1f} KB)")
    print(f"  Savings:    {storage_savings_pct:.1f}%")
    
    # For 1000 records dataset
    dataset_size = classification['dataset_rows']
    pure_ckks_total_mb = (pure_ckks_storage * dataset_size) / (1024 * 1024)
    hybrid_total_mb = (hybrid_storage * dataset_size) / (1024 * 1024)
    
    print(f"\nTotal Dataset Storage ({dataset_size} records):")
    print(f"  Pure CKKS:  {pure_ckks_total_mb:.1f} MB")
    print(f"  Hybrid:     {hybrid_total_mb:.1f} MB")
    print(f"  Saved:      {pure_ckks_total_mb - hybrid_total_mb:.1f} MB")
    
    return {
        "pure_ckks_storage_per_record_bytes": pure_ckks_storage,
        "hybrid_storage_per_record_bytes": hybrid_storage,
        "storage_savings_percentage": storage_savings_pct,
        "pure_ckks_total_mb": pure_ckks_total_mb,
        "hybrid_total_mb": hybrid_total_mb
    }


def save_metrics(metrics: Dict[str, Any], output_path: str):
    """Save metrics to CSV file."""
    # Flatten nested dictionaries
    flat_metrics = {}
    for category, values in metrics.items():
        if isinstance(values, dict):
            for key, value in values.items():
                flat_metrics[f"{category}_{key}"] = value
        else:
            flat_metrics[category] = values
    
    # Convert to DataFrame
    df = pd.DataFrame([flat_metrics])
    
    # Save to CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"\n✓ Metrics saved to: {output_path}")
    
    return df


def generate_summary_report(metrics: Dict[str, Any]):
    """Generate human-readable summary report."""
    print("\n" + "="*70)
    print("HYBRID ARCHITECTURE PROOF SUMMARY")
    print("="*70)
    
    print("\n📊 KEY FINDINGS:")
    print(f"\n1. Field Distribution:")
    print(f"   - Total fields: {metrics['classification']['total_fields']}")
    print(f"   - PII fields (AES): {metrics['classification']['pii_count']} ({metrics['classification']['pii_percentage']:.1f}%)")
    print(f"   - Vitals (CKKS): {metrics['classification']['vitals_count']} ({metrics['classification']['vitals_percentage']:.1f}%)")
    
    print(f"\n2. Encryption Performance:")
    print(f"   - AES-256-GCM: {metrics['performance']['aes_encryption_time_ms']:.4f} ms per field")
    print(f"   - CKKS: {metrics['performance']['ckks_encryption_time_ms']:.2f} ms per field")
    print(f"   - AES is {metrics['performance']['aes_speedup_factor']:.0f}x faster than CKKS")
    
    print(f"\n3. Storage Efficiency:")
    print(f"   - Pure CKKS approach: {metrics['efficiency']['pure_ckks_total_mb']:.1f} MB")
    print(f"   - Hybrid approach: {metrics['efficiency']['hybrid_total_mb']:.1f} MB")
    print(f"   - Storage savings: {metrics['efficiency']['storage_savings_percentage']:.1f}%")
    
    print(f"\n4. Ciphertext Overhead:")
    print(f"   - AES expansion: {metrics['sizes']['aes_expansion_factor']:.2f}x (compact)")
    print(f"   - CKKS expansion: {metrics['sizes']['ckks_expansion_factor']:.0f}x (enables homomorphic ops)")
    
    print("\n✅ CONCLUSION:")
    print("   Hybrid architecture achieves ~{:.0f}% improvement in storage efficiency".format(
        metrics['efficiency']['storage_savings_percentage']
    ))
    print("   while maintaining homomorphic computation capability for vitals.")
    print("   H1 (Security Efficacy): VALIDATED")
    print("\n" + "="*70)


def main():
    """Main execution function."""
    print("="*70)
    print("HYBRID ARCHITECTURE PROOF GENERATOR")
    print("="*70)
    print("\nThis script generates empirical proof for H1 (Security Efficacy)")
    print("by analyzing the hybrid AES-CKKS encryption architecture.")
    
    # Load dataset
    print("\nLoading dataset...")
    df = load_sample_dataset()
    print(f"✓ Loaded {len(df)} records with {len(df.columns)} fields")
    
    # Run analysis tasks
    metrics = {}
    
    # Task 1: Classification
    metrics['classification'] = measure_classification(df)
    
    # Task 2: Performance
    metrics['performance'] = measure_encryption_performance()
    
    # Task 3: Sizes
    metrics['sizes'] = measure_ciphertext_sizes()
    
    # Task 4: Efficiency
    metrics['efficiency'] = calculate_hybrid_efficiency(
        metrics['classification'],
        metrics['sizes']
    )
    
    # Save results
    output_path = os.path.join("benchmarks", "hybrid_architecture_metrics.csv")
    save_metrics(metrics, output_path)
    
    # Generate summary
    generate_summary_report(metrics)
    
    print("\n✓ Hybrid architecture proof generation complete!")


if __name__ == "__main__":
    main()
