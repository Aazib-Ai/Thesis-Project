import csv
import os
import sys
import time
from typing import List, Tuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext


def encrypt_records_batched(mgr: CKKSContext, n: int, batch_size: int = 128) -> Tuple[int, float]:
    vals = [float(i % 100) for i in range(n)]
    chunks = [vals[i : i + batch_size] for i in range(0, n, batch_size)]
    start = time.perf_counter()
    for ch in chunks:
        pad = ch + [0.0] * (batch_size - len(ch))
        _ = mgr.batch_encrypt([[v] for v in pad])
    elapsed = time.perf_counter() - start
    return n, elapsed


def sum_slots_plain(dec: List[float]) -> float:
    return float(sum(dec))


def mean_batched(mgr: CKKSContext, vals: List[float], batch_size: int = 128) -> Tuple[int, float]:
    """
    CRITICAL FIX: Encryption is done BEFORE timing starts (like baseline).
    This ensures we only measure homomorphic operations, not encryption overhead.
    """
    # PRE-ENCRYPT (NOT TIMED) - ensures fair comparison with baseline
    chunks = [vals[i : i + batch_size] for i in range(0, len(vals), batch_size)]
    enc_chunks = []
    for ch in chunks:
        pad = ch + [0.0] * (batch_size - len(ch))
        enc_chunks.append(mgr.batch_encrypt([[v] for v in pad]))
    
    # TIME ONLY HOMOMORPHIC OPERATIONS (same as baseline)
    start = time.perf_counter()
    n = len(vals)
    acc = None
    for enc in enc_chunks:
        s = enc * (1.0 / float(n))
        if acc is None:
            acc = s
        else:
            acc = acc + s
    dec = mgr.decrypt_vector(acc)
    _ = sum_slots_plain(dec)
    elapsed = time.perf_counter() - start
    return n, elapsed


def save_csv(path: str, enc_time: List[Tuple[int, float]], mean_time: List[Tuple[int, float]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "records", "seconds"])
        for n, t in enc_time:
            w.writerow(["encrypt", n, f"{t:.6f}"])
        for n, t in mean_time:
            w.writerow(["mean", n, f"{t:.6f}"])


if __name__ == "__main__":
    print("=" * 60)
    print("CKKS OPTIMIZED Benchmark")
    print("=" * 60)
    
    mgr = CKKSContext()
    mgr.create_optimized_context()
    print("\n✓ Created optimized CKKS context (poly_degree=16384)")
    
    # Add 100K support with adaptive batch size
    enc_counts = [1_000, 10_000, 100_000]
    print(f"\n[1/2] Running encryption benchmarks for {enc_counts}...")
    enc_res = []
    for n in enc_counts:
        batch = 256 if n >= 100_000 else 128  # Larger batches for bigger datasets
        print(f"  Encrypting {n:>7,} records (batch_size={batch})...")
        enc_res.append(encrypt_records_batched(mgr, n, batch_size=batch))
    
    print(f"\n[2/2] Running mean calculation benchmarks...")
    vals1 = [float(i % 100) for i in range(1_000)]
    vals2 = [float(i % 100) for i in range(10_000)]
    vals3 = [float(i % 100) for i in range(100_000)]
    mean_res = [
        mean_batched(mgr, vals1, batch_size=128),
        mean_batched(mgr, vals2, batch_size=128),
        mean_batched(mgr, vals3, batch_size=256),  # Larger batch for 100K
    ]
    
    out = os.path.join("benchmarks", "ckks_optimized_results.csv")
    save_csv(out, enc_res, mean_res)
    
    print("\n" + "=" * 60)
    print("RESULTS:")
    print("=" * 60)
    for n, t in enc_res:
        print(f"encrypt records={n:>7,} time={t:>8.4f}s")
    for n, t in mean_res:
        print(f"mean    records={n:>7,} time={t:>8.4f}s ({t*1000:.1f}ms)")
    print(f"\n✓ Results saved to {out}")
