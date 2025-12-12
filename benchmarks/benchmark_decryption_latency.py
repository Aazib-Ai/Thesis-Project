#!/usr/bin/env python
"""
Decryption Latency Benchmark

Measures decryption latency for AES and CKKS to quantify end-to-end
response times for cloud analytics queries.

Metrics:
- AES decryption latency per record
- CKKS decryption latency per result
- Total end-to-end latency estimation

Output:
- benchmarks/decryption_latency_results.csv
- benchmarks/charts/decryption_latency.png
"""

import os
import sys
import csv
import time
import matplotlib.pyplot as plt
import pandas as pd
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto.aes_module import AESCipher
from src.crypto.ckks_module import CKKSContext
from src.analytics.statistics import homomorphic_mean

# Configuration
OUTPUT_DIR = "benchmarks"
CHARTS_DIR = os.path.join(OUTPUT_DIR, "charts")


def benchmark_aes_decryption(num_records: int) -> dict:
    """
    Benchmark AES decryption latency.
    
    Returns:
    - total_seconds: Total time to decrypt all records
    - per_record_ms: Average time per record in milliseconds
    - throughput: Records decrypted per second
    """
    print(f"  AES decryption for {num_records} records...")
    
    # Prepare encrypted data
    key = AESCipher.generate_key()
    pii_data = [f"Patient_{i}_John_Doe_123_Main_St" for i in range(num_records)]
    encrypted_data = [AESCipher.encrypt(data.encode('utf-8'), key) for data in pii_data]
    
    # Benchmark decryption
    start = time.perf_counter()
    for enc in encrypted_data:
        _ = AESCipher.decrypt(enc, key)
    elapsed = time.perf_counter() - start
    
    per_record_ms = (elapsed / num_records) * 1000
    throughput = num_records / elapsed if elapsed > 0 else 0
    
    print(f"    Total: {elapsed:.4f}s | Per record: {per_record_ms:.4f}ms | Throughput: {throughput:.0f} rec/s")
    
    return {
        "total_seconds": elapsed,
        "per_record_ms": per_record_ms,
        "throughput_rec_per_sec": throughput
    }


def benchmark_ckks_decryption(num_records: int) -> dict:
    """
    Benchmark CKKS decryption latency using SIMD batching.
    
    Uses SIMD parallelism: packs up to 8192 values per ciphertext
    to match the optimized encryption approach.
    
    Returns:
    - total_seconds: Total time to decrypt all results
    - per_result_ms: Average time per result in milliseconds
    - throughput: Results decrypted per second
    """
    print(f"  CKKS decryption for {num_records} results (SIMD batched)...")
    
    SIMD_SLOTS = 8192
    
    # Prepare encrypted data using SIMD batching
    ctx = CKKSContext()
    ctx.create_optimized_context()
    
    # Pack values into SIMD slots
    all_values = [98.6 + i * 0.1 for i in range(num_records)]
    encrypted_chunks = []
    
    for i in range(0, num_records, SIMD_SLOTS):
        chunk = all_values[i:i + SIMD_SLOTS]
        if len(chunk) < SIMD_SLOTS:
            chunk = chunk + [0.0] * (SIMD_SLOTS - len(chunk))
        encrypted_chunks.append(ctx.encrypt_vector(chunk))
    
    num_ciphertexts = len(encrypted_chunks)
    
    # Benchmark decryption of SIMD-packed ciphertexts
    start = time.perf_counter()
    for enc in encrypted_chunks:
        _ = ctx.decrypt_vector(enc)
    elapsed = time.perf_counter() - start
    
    # Calculate metrics per original record (not per ciphertext)
    per_result_ms = (elapsed / num_records) * 1000
    throughput = num_records / elapsed if elapsed > 0 else 0
    
    print(f"    {num_ciphertexts} ciphertexts | Total: {elapsed:.4f}s | Per record: {per_result_ms:.6f}ms | Throughput: {throughput:.0f} rec/s")
    
    return {
        "total_seconds": elapsed,
        "per_result_ms": per_result_ms,
        "throughput_res_per_sec": throughput
    }


def benchmark_end_to_end_latency(num_records: int) -> dict:
    """
    Estimate end-to-end latency for a complete analytics query using SIMD batching.
    
    Simulates:
    1. Client encrypts query parameters (AES)
    2. Server processes homomorphic computation (CKKS with SIMD)
    3. Server decrypts result (CKKS)
    4. Client receives and decrypts final result (AES if needed)
    
    Returns timing breakdown.
    """
    print(f"  End-to-end latency simulation ({num_records} records, SIMD batched)...")
    
    SIMD_SLOTS = 8192
    
    # Setup
    aes_key = AESCipher.generate_key()
    ctx = CKKSContext()
    ctx.create_optimized_context()
    
    # Generate data
    all_values = [98.6 + i * 0.1 for i in range(num_records)]
    
    # 1. Encryption time using SIMD batching
    encrypt_start = time.perf_counter()
    encrypted_chunks = []
    for i in range(0, num_records, SIMD_SLOTS):
        chunk = all_values[i:i + SIMD_SLOTS]
        chunk_size = len(chunk)
        if chunk_size < SIMD_SLOTS:
            chunk = chunk + [0.0] * (SIMD_SLOTS - chunk_size)
        encrypted_chunks.append((ctx.encrypt_vector(chunk), chunk_size))
    encrypt_time = time.perf_counter() - encrypt_start
    
    # 2. Homomorphic computation time (sum all chunks, then compute mean)
    compute_start = time.perf_counter()
    total_sum = None
    for enc, chunk_size in encrypted_chunks:
        if total_sum is None:
            total_sum = enc
        else:
            total_sum = total_sum + enc
    
    # Decrypt and compute mean
    dec = ctx.decrypt_vector(total_sum)
    total = sum(dec[:min(num_records, SIMD_SLOTS)]) if num_records <= SIMD_SLOTS else sum(dec[:SIMD_SLOTS])
    mean_val = total / num_records
    compute_time = time.perf_counter() - compute_start
    
    # 3. Decryption time (already included in compute for SIMD approach)
    decrypt_start = time.perf_counter()
    # Final result is already decrypted in compute step, simulate single decrypt
    _ = ctx.decrypt_vector(total_sum)
    decrypt_time = time.perf_counter() - decrypt_start
    
    total_time = encrypt_time + compute_time + decrypt_time
    
    print(f"    Encrypt: {encrypt_time:.4f}s | Compute: {compute_time:.4f}s | Decrypt: {decrypt_time:.4f}s")
    print(f"    Total: {total_time:.4f}s | Mean: {mean_val:.4f}")
    
    return {
        "encrypt_seconds": encrypt_time,
        "compute_seconds": compute_time,
        "decrypt_seconds": decrypt_time,
        "total_seconds": total_time
    }


def run_decryption_benchmarks():
    """Run all decryption latency benchmarks"""
    print("\n" + "=" * 70)
    print("  Decryption Latency Benchmark")
    print("=" * 70)
    
    dataset_sizes = [1000, 5000]  # Reduced for faster testing
    results = []
    
    for size in dataset_sizes:
        print(f"\n📊 Dataset: {size} records")
        
        aes_metrics = benchmark_aes_decryption(size)
        ckks_metrics = benchmark_ckks_decryption(size)
        
        results.append({
            "num_records": size,
            "aes_total_sec": aes_metrics["total_seconds"],
            "aes_per_record_ms": aes_metrics["per_record_ms"],
            "aes_throughput": aes_metrics["throughput_rec_per_sec"],
            "ckks_total_sec": ckks_metrics["total_seconds"],
            "ckks_per_result_ms": ckks_metrics["per_result_ms"],
            "ckks_throughput": ckks_metrics["throughput_res_per_sec"]
        })
    
    # End-to-end latency for middle dataset
    print(f"\n📊 End-to-End Latency Analysis")
    e2e_metrics = benchmark_end_to_end_latency(dataset_sizes[1])  # Use 10K
    
    # Save results
    save_results(results, e2e_metrics)
    
    # Generate charts
    generate_latency_charts(results, e2e_metrics)
    
    return results


def save_results(results, e2e_metrics):
    """Save decryption latency results to CSV"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Main decryption results
    results_path = os.path.join(OUTPUT_DIR, "decryption_latency_results.csv")
    with open(results_path, 'w', newline='') as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    
    print(f"\n✅ Results saved to: {results_path}")
    
    # End-to-end latency
    e2e_path = os.path.join(OUTPUT_DIR, "end_to_end_latency_results.csv")
    with open(e2e_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=e2e_metrics.keys())
        writer.writeheader()
        writer.writerow(e2e_metrics)
    
    print(f"✅ End-to-end latency saved to: {e2e_path}")


def generate_latency_charts(results, e2e_metrics):
    """Generate decryption latency charts"""
    print("\n📊 Generating latency charts...")
    
    df = pd.DataFrame(results)
    
    # Create figure with 2 subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Chart 1: Per-Record/Result Latency
    x = range(len(df))
    width = 0.35
    
    ax1.bar([i - width/2 for i in x], df["aes_per_record_ms"], width,
            label='AES (per record)', color='#3498db', alpha=0.8)
    ax1.bar([i + width/2 for i in x], df["ckks_per_result_ms"], width,
            label='CKKS (per result)', color='#e74c3c', alpha=0.8)
    
    ax1.set_xlabel('Dataset Size', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Decryption Time (ms)', fontsize=12, fontweight='bold')
    ax1.set_title('Decryption Latency per Item', fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{r['num_records']//1000}K" for r in results])
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)
    
    # Chart 2: End-to-End Breakdown
    operations = ['Encrypt', 'Compute', 'Decrypt']
    times = [
        e2e_metrics["encrypt_seconds"],
        e2e_metrics["compute_seconds"],
        e2e_metrics["decrypt_seconds"]
    ]
    colors = ['#3498db', '#9b59b6', '#e74c3c']
    
    ax2.bar(operations, times, color=colors, alpha=0.8)
    ax2.set_ylabel('Time (seconds)', fontsize=12, fontweight='bold')
    ax2.set_title('End-to-End Latency Breakdown (10K records)', fontsize=14, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    # Add total time annotation
    total = e2e_metrics["total_seconds"]
    ax2.text(1, max(times) * 0.9, f'Total: {total:.2f}s', 
             ha='center', fontsize=11, fontweight='bold',
             bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    
    # Save chart
    os.makedirs(CHARTS_DIR, exist_ok=True)
    chart_path = os.path.join(CHARTS_DIR, "decryption_latency.png")
    plt.savefig(chart_path, dpi=300, bbox_inches='tight')
    print(f"✅ Chart saved: {chart_path}")
    plt.close()


if __name__ == "__main__":
    try:
        results = run_decryption_benchmarks()
        
        print("\n" + "=" * 70)
        print("  Decryption Latency Summary")
        print("=" * 70)
        
        for r in results:
            print(f"  {r['num_records']:>6} records: AES={r['aes_per_record_ms']:.4f}ms/rec  "
                  f"CKKS={r['ckks_per_result_ms']:.2f}ms/res")
        
        print("\n✅ Decryption latency benchmark completed successfully!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
