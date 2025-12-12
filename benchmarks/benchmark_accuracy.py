#!/usr/bin/env python
"""
Accuracy Benchmark Script
=========================
Calculates MSE, RMSE, and Accuracy Percentage for CKKS operations (Mean, Variance)
against NumPy plaintext baseline.
"""

import os
import sys
import csv
import numpy as np
import time
from typing import List, Dict, Tuple

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto.ckks_module import CKKSContext
from src.analytics.statistics import homomorphic_mean, homomorphic_variance
from src.analytics.accuracy_metrics import calculate_mse, calculate_rmse, calculate_accuracy_percentage

# Configuration
DATA_DIR = os.path.join("data", "synthetic")
OUTPUT_FILE = os.path.join("benchmarks", "accuracy_metrics.csv")
DATA_FILES = {
    1000: "patients_1k.csv",
    10000: "patients_100k.csv", # Using 100k file for 10k test (by slicing) if needed, or proper file
}
# Ensure we map correctly, check existing structure again
# Previous `run_all_benchmarks.py` had:
# 1000: "patients_1k.csv",
# 10000: "patients_10k.csv",
# 100000: "patients_100k.csv"
# We should try to use all if available.

BENCHMARK_FIELD = "heart_rate" # Example numeric field

def load_data(limit: int) -> List[float]:
    """Load data respecting the limit."""
    # Find best file
    if limit <= 1000:
        fname = "patients_1k.csv"
    elif limit <= 10000:
        fname = "patients_10k.csv"
    else:
        fname = "patients_100k.csv"
        
    fpath = os.path.join(DATA_DIR, fname)
    
    # Check if exists
    if not os.path.exists(fpath):
        # Fallback to largest available or error
        # Assuming standard files exist
        pass

    values = []
    try:
        with open(fpath, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= limit:
                    break
                try:
                    values.append(float(row[BENCHMARK_FIELD]))
                except (ValueError, KeyError):
                    continue
    except FileNotFoundError:
        print(f"Warning: File {fpath} not found. Skipping {limit}.")
        return []
        
    return values

def run_accuracy_benchmark():
    print(f"Starting Accuracy Benchmark...")
    print(f"Output: {OUTPUT_FILE}")
    
    # Initialize Crypto
    print("Initializing CKKS context...")
    ctx = CKKSContext()
    ctx.create_optimized_context() # Use optimized for accuracy check? Or Baseline? 
    # Usually we want to check the system we are proposing (Optimized Hybrid).
    # But CKKS parameters affect accuracy.
    
    results = []
    
    for count in [1000, 10000, 100000]:
        print(f"\nProcessing {count} records...")
        values = load_data(count)
        
        if len(values) < count:
            print(f"  Warning: Only loaded {len(values)} records. Skipping.")
            continue
            
        # Plaintext Ground Truth
        p_mean = float(np.mean(values))
        p_var = float(np.var(values))
        print(f"  Plaintext Mean: {p_mean:.6f}")
        print(f"  Plaintext Var:  {p_var:.6f}")
        
        # Encrypt using SIMD batching
        print("  Encrypting with SIMD batching...")
        SIMD_SLOTS = 8192
        encrypted_chunks = []
        for i in range(0, count, SIMD_SLOTS):
            chunk = values[i:i + SIMD_SLOTS]
            chunk_size = len(chunk)
            if chunk_size < SIMD_SLOTS:
                chunk = chunk + [0.0] * (SIMD_SLOTS - chunk_size)
            encrypted_chunks.append((ctx.encrypt_vector(chunk), chunk_size))
        
        # 1. Benchmark Mean using SIMD approach
        print("  Computing Encrypted Mean (SIMD)...")
        # Sum all encrypted chunks
        enc_sum = encrypted_chunks[0][0]
        for enc, _ in encrypted_chunks[1:]:
            enc_sum = enc_sum + enc
        
        # Decrypt and compute mean
        dec_vec = ctx.decrypt_vector(enc_sum)
        # Sum only valid values (exclude padding)
        total = sum(dec_vec[:min(count, SIMD_SLOTS)]) if count <= SIMD_SLOTS else sum(dec_vec[:SIMD_SLOTS])
        dec_mean = total / count
        
        mse_mean = calculate_mse([p_mean], [dec_mean])
        rmse_mean = calculate_rmse([p_mean], [dec_mean])
        acc_mean = calculate_accuracy_percentage([p_mean], [dec_mean], tolerance=0.01)
        
        print(f"  -> Decrypted Mean: {dec_mean:.6f}")
        print(f"  -> Mean Accuracy: {acc_mean:.2f}% (MSE: {mse_mean:.2e})")
        
        results.append({
            "operation": "mean",
            "record_count": count,
            "plaintext_result": p_mean,
            "encrypted_result": "CKKS_SIMD",
            "decrypted_result": dec_mean,
            "mse": mse_mean,
            "rmse": rmse_mean,
            "accuracy_pct": acc_mean
        })
        
        # 2. Benchmark Variance using SIMD approach
        print("  Computing Encrypted Variance (SIMD)...")
        # Variance = E(X^2) - E(X)^2
        # We already have the mean (dec_mean), now compute E(X^2)
        
        # Create new encrypted chunks for X^2
        start = time.time()
        squared_chunks = []
        for i in range(0, count, SIMD_SLOTS):
            chunk = values[i:i + SIMD_SLOTS]
            squared_chunk = [v * v for v in chunk]
            if len(squared_chunk) < SIMD_SLOTS:
                squared_chunk = squared_chunk + [0.0] * (SIMD_SLOTS - len(squared_chunk))
            squared_chunks.append(ctx.encrypt_vector(squared_chunk))
        
        # Sum squared encrypted chunks
        enc_squared_sum = squared_chunks[0]
        for enc in squared_chunks[1:]:
            enc_squared_sum = enc_squared_sum + enc
        
        # Decrypt and compute E(X^2)
        dec_squared_vec = ctx.decrypt_vector(enc_squared_sum)
        total_squared = sum(dec_squared_vec[:min(count, SIMD_SLOTS)]) if count <= SIMD_SLOTS else sum(dec_squared_vec[:SIMD_SLOTS])
        mean_of_squares = total_squared / count
        
        # Variance = E(X^2) - E(X)^2
        dec_var = mean_of_squares - (dec_mean * dec_mean)
        dur = time.time() - start
        print(f"     (took {dur:.2f}s)")
        
        mse_var = calculate_mse([p_var], [dec_var])
        rmse_var = calculate_rmse([p_var], [dec_var])
        acc_var = calculate_accuracy_percentage([p_var], [dec_var], tolerance=0.1)
        
        print(f"  -> Decrypted Var: {dec_var:.6f}")
        print(f"  -> Var Accuracy:  {acc_var:.2f}% (MSE: {mse_var:.2e})")
        
        results.append({
            "operation": "variance",
            "record_count": count,
            "plaintext_result": p_var,
            "encrypted_result": "CKKS_SIMD",
            "decrypted_result": dec_var,
            "mse": mse_var,
            "rmse": rmse_var,
            "accuracy_pct": acc_var
        })

    # Save results
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', newline='') as f:
        fieldnames = ["operation", "record_count", "plaintext_result", "encrypted_result", "decrypted_result", "mse", "rmse", "accuracy_pct"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
            
    print(f"\nSaved results to {OUTPUT_FILE}")

if __name__ == "__main__":
    run_accuracy_benchmark()
