import os
import sys
import time
import csv
import numpy as np
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext
from src.analytics.statistics import homomorphic_mean


def ensure_dir(p):
    os.makedirs(os.path.dirname(p), exist_ok=True)


def run_ckks_mean(values):
    """Calculate mean using CKKS with SIMD batching for optimized performance."""
    SIMD_SLOTS = 8192
    n = len(values)
    
    ck = CKKSContext()
    ck.create_optimized_context()
    
    # Pack values into SIMD slots
    encrypted_chunks = []
    for i in range(0, n, SIMD_SLOTS):
        chunk = [float(v) for v in values[i:i + SIMD_SLOTS]]
        if len(chunk) < SIMD_SLOTS:
            chunk = chunk + [0.0] * (SIMD_SLOTS - len(chunk))
        encrypted_chunks.append(ck.encrypt_vector(chunk))
    
    start = time.perf_counter()
    
    # Sum all encrypted chunks
    acc = encrypted_chunks[0]
    for v in encrypted_chunks[1:]:
        acc = acc + v
    
    # Decrypt and compute mean
    dec = ck.decrypt_vector(acc)
    total = sum(dec[:min(n, SIMD_SLOTS)]) if n <= SIMD_SLOTS else sum(dec[:SIMD_SLOTS])
    val = total / n
    
    elapsed = time.perf_counter() - start
    return val, elapsed


def run_bfv_mean(values):
    bf = CKKSContext()
    bf.create_bfv_context()
    # encrypt each integer as single-slot vector
    encs = [bf.bfv_encrypt([int(v)]) for v in values]
    start = time.perf_counter()
    acc = encs[0]
    for v in encs[1:]:
        acc = acc + v
    total = bf.bfv_decrypt(acc)[0]
    if total < 0:
        total += bf.bfv_plain_modulus
    mean_val = total / len(values)
    elapsed = time.perf_counter() - start
    return mean_val, elapsed


if __name__ == "__main__":
    path = os.path.join("data", "synthetic", "patients_10k.csv")
    df = pd.read_csv(path)
    hr = df["heart_rate"].astype(int).tolist()
    # limit to 10k rows if file larger
    hr = hr[:10000]
    plain_mean = float(np.mean(hr))

    ckks_mean, ckks_t = run_ckks_mean(hr)
    bfv_mean, bfv_t = run_bfv_mean(hr)

    out = os.path.join("benchmarks", "scheme_comparison.csv")
    ensure_dir(out)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scheme", "records", "mean_time_sec", "mean_value", "plain_mean", "abs_error"])
        w.writerow(["CKKS", len(hr), f"{ckks_t:.6f}", f"{ckks_mean:.6f}", f"{plain_mean:.6f}", f"{abs(ckks_mean-plain_mean):.6f}"])
        w.writerow(["BFV", len(hr), f"{bfv_t:.6f}", f"{bfv_mean:.6f}", f"{plain_mean:.6f}", f"{abs(bfv_mean-plain_mean):.6f}"])
    print("Saved:", out)
