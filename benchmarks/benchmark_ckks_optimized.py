"""
CKKS OPTIMIZED Benchmark - Using TRUE SIMD Parallelism

The key optimization is leveraging CKKS's SIMD capabilities:
- With poly_modulus_degree=16384, we have 8192 "slots"
- We can pack up to 8192 values into ONE ciphertext
- Operations are performed in PARALLEL across all slots
- This reduces O(n) ciphertext operations to O(n/8192) = ~O(1) for most datasets
"""
import csv
import os
import sys
import time
from typing import List, Tuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext
from src.crypto.columnar_encryption import ColumnarEncryptor
from src.analytics.columnar_statistics import ColumnarStatistics


# For poly_degree=16384, we have 8192 SIMD slots available
SIMD_SLOTS = 8192


def encrypt_simd_optimized(mgr: CKKSContext, encryptor: ColumnarEncryptor, n: int) -> Tuple[int, float]:
    """
    Columnar encryption using ColumnarEncryptor (same as app).
    Simulates encrypting a single column of n values.
    """
    # Create a fake column of data
    column_data = {"test_field": [float(i % 100) for i in range(n)]}
    
    start = time.perf_counter()
    # Use the same encryption path as the app
    encrypted_columns, metadata = encryptor.encrypt_columns(column_data)
    elapsed = time.perf_counter() - start
    
    return n, elapsed


def mean_simd_optimized(mgr: CKKSContext, encryptor: ColumnarEncryptor, vals: List[float]) -> Tuple[int, float]:
    """
    TRUE SIMD mean calculation using ColumnarStatistics (same as app).
    
    This uses the exact same code path as the app's analytics endpoints.
    The computation stays encrypted throughout.
    """
    n = len(vals)
    
    # Pre-encrypt using columnar approach (not timed, same as baseline)
    column_data = {"test_field": vals}
    encrypted_columns, metadata = encryptor.encrypt_columns(column_data)
    enc_col = encrypted_columns["test_field"]
    
    # TIME ONLY THE HOMOMORPHIC OPERATIONS (same as app)
    start = time.perf_counter()
    
    # Use ColumnarStatistics.compute_operation (same as app)
    enc_mean = ColumnarStatistics.compute_operation(enc_col, 'mean')
    
    # Decrypt only to verify result (app would send encrypted to client)
    result = mgr.decrypt_vector(enc_mean)
    mean_val = result[0]
    
    elapsed = time.perf_counter() - start
    return n, elapsed


def variance_simd_optimized(mgr: CKKSContext, encryptor: ColumnarEncryptor, vals: List[float]) -> Tuple[int, float]:
    """
    TRUE SIMD variance calculation using ColumnarStatistics (same as app).
    
    Uses Var(X) = E[X²] - E[X]² formula homomorphically.
    """
    n = len(vals)
    
    # Pre-encrypt using columnar approach
    column_data = {"test_field": vals}
    encrypted_columns, metadata = encryptor.encrypt_columns(column_data)
    enc_col = encrypted_columns["test_field"]
    
    # TIME ONLY THE HOMOMORPHIC OPERATIONS
    start = time.perf_counter()
    
    # Use ColumnarStatistics.compute_operation (same as app)
    enc_variance = ColumnarStatistics.compute_operation(enc_col, 'variance')
    
    # Decrypt only to verify result
    result = mgr.decrypt_vector(enc_variance)
    variance_val = result[0]
    
    elapsed = time.perf_counter() - start
    return n, elapsed


def sum_simd_optimized(mgr: CKKSContext, encryptor: ColumnarEncryptor, vals: List[float]) -> Tuple[int, float]:
    """
    TRUE SIMD sum calculation using ColumnarStatistics (same as app).
    
    Sums all slots in the encrypted vector without decryption.
    """
    n = len(vals)
    
    # Pre-encrypt using columnar approach
    column_data = {"test_field": vals}
    encrypted_columns, metadata = encryptor.encrypt_columns(column_data)
    enc_col = encrypted_columns["test_field"]
    
    # TIME ONLY THE HOMOMORPHIC OPERATIONS
    start = time.perf_counter()
    
    # Use ColumnarStatistics.compute_operation (same as app)
    enc_sum = ColumnarStatistics.compute_operation(enc_col, 'sum')
    
    # Decrypt only to verify result
    result = mgr.decrypt_vector(enc_sum)
    sum_val = result[0]
    
    elapsed = time.perf_counter() - start
    return n, elapsed


def save_csv(path: str, enc_time: List[Tuple[int, float]], mean_time: List[Tuple[int, float]], 
              variance_time: List[Tuple[int, float]], sum_time: List[Tuple[int, float]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "records", "seconds"])
        for n, t in enc_time:
            w.writerow(["encrypt", n, f"{t:.6f}"])
        for n, t in mean_time:
            w.writerow(["mean", n, f"{t:.6f}"])
        for n, t in variance_time:
            w.writerow(["variance", n, f"{t:.6f}"])
        for n, t in sum_time:
            w.writerow(["sum", n, f"{t:.6f}"])


if __name__ == "__main__":
    print("=" * 60)
    print("CKKS OPTIMIZED Benchmark (Using Columnar Architecture)")
    print("=" * 60)
    print(f"Using {SIMD_SLOTS} SIMD slots per ciphertext")
    
    mgr = CKKSContext()
    mgr.create_optimized_context()
    print("\n✓ Created optimized CKKS context (poly_degree=16384)")
    
    # Initialize ColumnarEncryptor (same as app)
    encryptor = ColumnarEncryptor(mgr, simd_slot_count=SIMD_SLOTS)
    print("✓ Initialized ColumnarEncryptor")
    
    enc_counts = [1_000, 10_000, 100_000]
    print(f"\n[1/4] Running columnar encryption benchmarks for {enc_counts}...")
    enc_res = []
    for n in enc_counts:
        num_ciphertexts = (n + SIMD_SLOTS - 1) // SIMD_SLOTS
        print(f"  {n:>7,} records -> {num_ciphertexts} ciphertext(s)")
        enc_res.append(encrypt_simd_optimized(mgr, encryptor, n))
    
    print(f"\n[2/4] Running mean calculation benchmarks...")
    vals1 = [float(i % 100) for i in range(1_000)]
    vals2 = [float(i % 100) for i in range(10_000)]
    vals3 = [float(i % 100) for i in range(100_000)]
    
    mean_res = [
        mean_simd_optimized(mgr, encryptor, vals1),
        mean_simd_optimized(mgr, encryptor, vals2),
        mean_simd_optimized(mgr, encryptor, vals3),
    ]
    
    print(f"\n[3/4] Running variance calculation benchmarks...")
    variance_res = [
        variance_simd_optimized(mgr, encryptor, vals1),
        variance_simd_optimized(mgr, encryptor, vals2),
        variance_simd_optimized(mgr, encryptor, vals3),
    ]
    
    print(f"\n[4/4] Running sum calculation benchmarks...")
    sum_res = [
        sum_simd_optimized(mgr, encryptor, vals1),
        sum_simd_optimized(mgr, encryptor, vals2),
        sum_simd_optimized(mgr, encryptor, vals3),
    ]
    
    out = os.path.join("benchmarks", "ckks_optimized_results.csv")
    save_csv(out, enc_res, mean_res, variance_res, sum_res)
    
    print("\n" + "=" * 60)
    print("RESULTS:")
    print("=" * 60)
    for n, t in enc_res:
        ciphertexts = (n + SIMD_SLOTS - 1) // SIMD_SLOTS
        print(f"encrypt  records={n:>7,} ({ciphertexts} ctx) time={t:>8.4f}s")
    for n, t in mean_res:
        print(f"mean     records={n:>7,} time={t:>8.4f}s ({t*1000:.1f}ms)")
    for n, t in variance_res:
        print(f"variance records={n:>7,} time={t:>8.4f}s ({t*1000:.1f}ms)")
    for n, t in sum_res:
        print(f"sum      records={n:>7,} time={t:>8.4f}s ({t*1000:.1f}ms)")
    print(f"\n✓ Results saved to {out}")

