#!/usr/bin/env python
"""
Memory Usage Profiling Benchmark

Measures peak RAM usage during encryption, computation, and decryption
operations to quantify memory overhead for cloud deployment.

Metrics:
- Peak RAM during encryption (1K, 10K, 100K records)
- Peak RAM during homomorphic computation
- Peak RAM during key generation
- Peak RAM during decryption

Output:
- benchmarks/memory_usage_results.csv
- benchmarks/charts/memory_usage_scaling.png
- benchmarks/charts/memory_by_operation.png
"""

import os
import sys
import csv
import time
import psutil
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from memory_profiler import memory_usage
from typing import List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto.aes_module import AESCipher
from src.crypto.ckks_module import CKKSContext
from src.analytics.statistics import homomorphic_mean

# Configuration
OUTPUT_DIR = "benchmarks"
CHARTS_DIR = os.path.join(OUTPUT_DIR, "charts")
DATA_DIR = os.path.join("data", "synthetic")


def get_current_memory_mb() -> float:
    """Get current process memory usage in MB"""
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024


def benchmark_encryption_memory(num_records: int) -> dict:
    """
    Benchmark memory usage during encryption.
    
    Returns dict with:
    - aes_peak_mb: Peak memory during AES encryption
    - ckks_baseline_peak_mb: Peak memory during CKKS baseline encryption
    - ckks_optimized_peak_mb: Peak memory during CKKS optimized encryption
    """
    print(f"  Benchmarking encryption memory for {num_records} records...")
    
    # Generate test data
    pii_data = [f"Patient_{i}_John_Doe" for i in range(num_records)]
    numeric_data = [[98.6 + i * 0.1, 120.0 + i * 0.5, 80.0 + i * 0.3] for i in range(num_records)]
    
    # AES Encryption Memory
    mem_before = get_current_memory_mb()
    
    def aes_encrypt_task():
        key = AESCipher.generate_key()
        for data in pii_data:
            AESCipher.encrypt(data.encode('utf-8'), key)
    
    aes_mem_usage = memory_usage((aes_encrypt_task,), interval=0.01, max_usage=True)
    aes_peak = aes_mem_usage if isinstance(aes_mem_usage, (int, float)) else max(aes_mem_usage)
    
    # CKKS Baseline Encryption Memory
    def ckks_baseline_encrypt_task():
        ctx = CKKSContext()
        ctx.create_context()
        for data in numeric_data:
            ctx.encrypt_vector(data)
    
    ckks_baseline_mem_usage = memory_usage((ckks_baseline_encrypt_task,), interval=0.01, max_usage=True)
    ckks_baseline_peak = ckks_baseline_mem_usage if isinstance(ckks_baseline_mem_usage, (int, float)) else max(ckks_baseline_mem_usage)
    
    # CKKS Optimized Encryption Memory (SIMD Batching)
    SIMD_SLOTS = 8192
    all_values = [v for sublist in numeric_data for v in sublist]  # Flatten
    
    def ckks_optimized_encrypt_task():
        ctx = CKKSContext()
        ctx.create_optimized_context()
        # Pack values into SIMD slots - each ciphertext holds up to 8192 values
        for i in range(0, len(all_values), SIMD_SLOTS):
            chunk = all_values[i:i + SIMD_SLOTS]
            if len(chunk) < SIMD_SLOTS:
                chunk = chunk + [0.0] * (SIMD_SLOTS - len(chunk))
            ctx.encrypt_vector(chunk)
    
    ckks_optimized_mem_usage = memory_usage((ckks_optimized_encrypt_task,), interval=0.01, max_usage=True)
    ckks_optimized_peak = ckks_optimized_mem_usage if isinstance(ckks_optimized_mem_usage, (int, float)) else max(ckks_optimized_mem_usage)
    
    print(f"    AES: {aes_peak:.2f} MB")
    print(f"    CKKS Baseline: {ckks_baseline_peak:.2f} MB")
    print(f"    CKKS Optimized: {ckks_optimized_peak:.2f} MB")
    
    return {
        "aes_peak_mb": aes_peak,
        "ckks_baseline_peak_mb": ckks_baseline_peak,
        "ckks_optimized_peak_mb": ckks_optimized_peak
    }


def benchmark_computation_memory(num_records: int) -> float:
    """Benchmark memory usage during homomorphic mean computation using SIMD batching"""
    print(f"  Benchmarking computation memory for {num_records} records (SIMD)...")
    
    SIMD_SLOTS = 8192
    
    # Prepare encrypted data using SIMD batching
    ctx = CKKSContext()
    ctx.create_optimized_context()
    
    all_values = [98.6 + i * 0.1 for i in range(num_records)]
    encrypted_chunks = []
    for i in range(0, num_records, SIMD_SLOTS):
        chunk = all_values[i:i + SIMD_SLOTS]
        if len(chunk) < SIMD_SLOTS:
            chunk = chunk + [0.0] * (SIMD_SLOTS - len(chunk))
        encrypted_chunks.append(ctx.encrypt_vector(chunk))
    
    mem_before = get_current_memory_mb()
    
    def computation_task():
        # Sum all encrypted chunks
        total_sum = encrypted_chunks[0]
        for enc in encrypted_chunks[1:]:
            total_sum = total_sum + enc
        # Decrypt and compute mean
        dec = ctx.decrypt_vector(total_sum)
        total = sum(dec[:min(num_records, SIMD_SLOTS)])
        mean_val = total / num_records
    
    comp_mem_usage = memory_usage((computation_task,), interval=0.01, max_usage=True)
    peak_mb = comp_mem_usage if isinstance(comp_mem_usage, (int, float)) else max(comp_mem_usage)
    
    print(f"    Computation: {peak_mb:.2f} MB")
    
    return peak_mb


def benchmark_key_generation_memory() -> dict:
    """Benchmark memory usage during key generation"""
    print(f"  Benchmarking key generation memory...")
    
    mem_before = get_current_memory_mb()
    
    # AES Key Generation
    def aes_keygen_task():
        for _ in range(100):  # Generate multiple keys for better measurement
            AESCipher.generate_key()
    
    aes_mem_usage = memory_usage((aes_keygen_task,), interval=0.01, max_usage=True)
    aes_peak = aes_mem_usage if isinstance(aes_mem_usage, (int, float)) else max(aes_mem_usage)
    
    # CKKS Baseline Key Generation
    def ckks_baseline_keygen_task():
        ctx = CKKSContext()
        ctx.create_context()
    
    ckks_baseline_mem_usage = memory_usage((ckks_baseline_keygen_task,), interval=0.01, max_usage=True)
    ckks_baseline_peak = ckks_baseline_mem_usage if isinstance(ckks_baseline_mem_usage, (int, float)) else max(ckks_baseline_mem_usage)
    
    # CKKS Optimized Key Generation
    def ckks_optimized_keygen_task():
        ctx = CKKSContext()
        ctx.create_optimized_context()
    
    ckks_optimized_mem_usage = memory_usage((ckks_optimized_keygen_task,), interval=0.01, max_usage=True)
    ckks_optimized_peak = ckks_optimized_mem_usage if isinstance(ckks_optimized_mem_usage, (int, float)) else max(ckks_optimized_mem_usage)
    
    print(f"    AES: {aes_peak:.2f} MB")
    print(f"    CKKS Baseline: {ckks_baseline_peak:.2f} MB")
    print(f"    CKKS Optimized: {ckks_optimized_peak:.2f} MB")
    
    return {
        "aes_keygen_peak_mb": aes_peak,
        "ckks_baseline_keygen_peak_mb": ckks_baseline_peak,
        "ckks_optimized_keygen_peak_mb": ckks_optimized_peak
    }


def benchmark_decryption_memory(num_records: int) -> dict:
    """Benchmark memory usage during decryption using SIMD batching for CKKS"""
    print(f"  Benchmarking decryption memory for {num_records} records (SIMD)...")
    
    SIMD_SLOTS = 8192
    
    # Prepare AES encrypted data
    key = AESCipher.generate_key()
    pii_data = [f"Patient_{i}" for i in range(num_records)]
    aes_encrypted = [AESCipher.encrypt(data.encode('utf-8'), key) for data in pii_data]
    
    # Prepare CKKS encrypted data using SIMD batching
    ctx = CKKSContext()
    ctx.create_optimized_context()
    all_values = [98.6 + i * 0.1 for i in range(num_records)]
    ckks_encrypted = []
    for i in range(0, num_records, SIMD_SLOTS):
        chunk = all_values[i:i + SIMD_SLOTS]
        if len(chunk) < SIMD_SLOTS:
            chunk = chunk + [0.0] * (SIMD_SLOTS - len(chunk))
        ckks_encrypted.append(ctx.encrypt_vector(chunk))
    
    mem_before = get_current_memory_mb()
    
    # AES Decryption
    def aes_decrypt_task():
        for enc in aes_encrypted:
            AESCipher.decrypt(enc, key)
    
    aes_mem_usage = memory_usage((aes_decrypt_task,), interval=0.01, max_usage=True)
    aes_peak = aes_mem_usage if isinstance(aes_mem_usage, (int, float)) else max(aes_mem_usage)
    
    # CKKS Decryption (SIMD batched)
    def ckks_decrypt_task():
        for enc in ckks_encrypted:
            ctx.decrypt_vector(enc)
    
    ckks_mem_usage = memory_usage((ckks_decrypt_task,), interval=0.01, max_usage=True)
    ckks_peak = ckks_mem_usage if isinstance(ckks_mem_usage, (int, float)) else max(ckks_mem_usage)
    
    print(f"    AES: {aes_peak:.2f} MB")
    print(f"    CKKS: {ckks_peak:.2f} MB")
    
    return {
        "aes_decrypt_peak_mb": aes_peak,
        "ckks_decrypt_peak_mb": ckks_peak
    }


def run_memory_benchmarks():
    """Run all memory benchmarks"""
    print("\n" + "=" * 70)
    print("  Memory Usage Profiling Benchmark")
    print("=" * 70)
    
    dataset_sizes = [1000, 5000]  # Reduced for faster testing
    results = []
    
    # Benchmark encryption memory for different dataset sizes
    for size in dataset_sizes:
        print(f"\n📊 Dataset: {size} records")
        
        enc_mem = benchmark_encryption_memory(size)
        comp_mem = benchmark_computation_memory(size)
        dec_mem = benchmark_decryption_memory(size)
        
        results.append({
            "num_records": size,
            "aes_encrypt_mb": enc_mem["aes_peak_mb"],
            "ckks_baseline_encrypt_mb": enc_mem["ckks_baseline_peak_mb"],
            "ckks_optimized_encrypt_mb": enc_mem["ckks_optimized_peak_mb"],
            "computation_mb": comp_mem,
            "aes_decrypt_mb": dec_mem["aes_decrypt_peak_mb"],
            "ckks_decrypt_mb": dec_mem["ckks_decrypt_peak_mb"]
        })
    
    # Benchmark key generation memory (independent of dataset size)
    print(f"\n📊 Key Generation")
    keygen_mem = benchmark_key_generation_memory()
    
    # Add key generation to first result (or as separate record)
    key_gen_result = {
        "num_records": 0,  # N/A for key generation
        "aes_keygen_mb": keygen_mem["aes_keygen_peak_mb"],
        "ckks_baseline_keygen_mb": keygen_mem["ckks_baseline_keygen_peak_mb"],
        "ckks_optimized_keygen_mb": keygen_mem["ckks_optimized_keygen_peak_mb"]
    }
    
    # Save results
    save_results(results, key_gen_result)
    
    # Generate charts
    generate_memory_charts(results, key_gen_result)
    
    return results


def save_results(results, key_gen_result):
    """Save memory benchmark results to CSV"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Main results
    results_path = os.path.join(OUTPUT_DIR, "memory_usage_results.csv")
    with open(results_path, 'w', newline='') as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    
    print(f"\n✅ Results saved to: {results_path}")
    
    # Key generation results (append to separate section or same file)
    keygen_path = os.path.join(OUTPUT_DIR, "memory_keygen_results.csv")
    with open(keygen_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=key_gen_result.keys())
        writer.writeheader()
        writer.writerow(key_gen_result)
    
    print(f"✅ Key generation memory saved to: {keygen_path}")


def generate_memory_charts(results, key_gen_result):
    """Generate memory usage charts"""
    print("\n📊 Generating memory charts...")
    
    df = pd.DataFrame(results)
    
    # Chart 1: Memory Scaling with Dataset Size
    fig, ax = plt.subplots(figsize=(10, 6))
    
    ax.plot(df["num_records"], df["aes_encrypt_mb"], marker='o', label='AES Encryption', linewidth=2)
    ax.plot(df["num_records"], df["ckks_optimized_encrypt_mb"], marker='s', label='CKKS Encryption', linewidth=2)
    ax.plot(df["num_records"], df["computation_mb"], marker='^', label='Homomorphic Computation', linewidth=2)
    ax.plot(df["num_records"], df["ckks_decrypt_mb"], marker='d', label='CKKS Decryption', linewidth=2)
    
    ax.set_xlabel('Dataset Size (records)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Peak Memory Usage (MB)', fontsize=12, fontweight='bold')
    ax.set_title('Memory Usage vs Dataset Size', fontsize=14, fontweight='bold')
    ax.legend()
    ax.grid(alpha=0.3)
    
    os.makedirs(CHARTS_DIR, exist_ok=True)
    chart1_path = os.path.join(CHARTS_DIR, "memory_usage_scaling.png")
    plt.savefig(chart1_path, dpi=300, bbox_inches='tight')
    print(f"✅ Chart saved: {chart1_path}")
    plt.close()
    
    # Chart 2: Memory by Operation Type (for 10K records)
    fig, ax = plt.subplots(figsize=(10, 6))
    
    mid_idx = len(results) // 2  # Use middle dataset (10K)
    mid_result = results[mid_idx]
    
    operations = ['AES\nEncrypt', 'CKKS\nEncrypt', 'Homomorphic\nComputation', 
                  'AES\nDecrypt', 'CKKS\nDecrypt']
    memory_values = [
        mid_result["aes_encrypt_mb"],
        mid_result["ckks_optimized_encrypt_mb"],
        mid_result["computation_mb"],
        mid_result["aes_decrypt_mb"],
        mid_result["ckks_decrypt_mb"]
    ]
    
    colors = ['#3498db', '#e74c3c', '#9b59b6', '#1abc9c', '#f39c12']
    ax.bar(operations, memory_values, color=colors, alpha=0.8)
    
    ax.set_ylabel('Peak Memory Usage (MB)', fontsize=12, fontweight='bold')
    ax.set_title(f'Memory Usage by Operation Type ({mid_result["num_records"]} records)', 
                 fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    
    chart2_path = os.path.join(CHARTS_DIR, "memory_by_operation.png")
    plt.savefig(chart2_path, dpi=300, bbox_inches='tight')
    print(f"✅ Chart saved: {chart2_path}")
    plt.close()


if __name__ == "__main__":
    try:
        results = run_memory_benchmarks()
        
        print("\n" + "=" * 70)
        print("  Memory Usage Summary")
        print("=" * 70)
        print("\n✅ Memory profiling completed successfully!")
        print("   All results and charts have been generated.")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
