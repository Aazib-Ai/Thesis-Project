import csv
import os
import sys
import time
from typing import List, Tuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.ckks_module import CKKSContext


def encrypt_many(mgr: CKKSContext, counts: List[int], vector_len: int = 1) -> List[Tuple[int, float]]:
    vec = [1.0] * vector_len
    results = []
    for n in counts:
        start = time.perf_counter()
        for _ in range(n):
            mgr.encrypt_vector(vec)
        elapsed = time.perf_counter() - start
        results.append((n, elapsed))
    return results


def homomorphic_mean_time(mgr: CKKSContext, n: int, vector_len: int = 16) -> float:
    vectors = [mgr.encrypt_vector([float(i % 10)] * vector_len) for i in range(n)]
    start = time.perf_counter()
    acc = vectors[0]
    for v in vectors[1:]:
        acc = mgr.add_encrypted(acc, v)
    scale = 1.0 / n
    acc = acc * scale
    _ = mgr.decrypt_vector(acc)
    return time.perf_counter() - start


def save_csv(path: str, enc_results: List[Tuple[int, float]], mean_results: List[Tuple[int, float]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "records", "seconds"])
        for n, t in enc_results:
            w.writerow(["encrypt", n, f"{t:.6f}"])
        for n, t in mean_results:
            w.writerow(["mean", n, f"{t:.6f}"])


if __name__ == "__main__":
    print("=" * 60)
    print("CKKS BASELINE (Non-Optimized) Benchmark")
    print("=" * 60)
    
    mgr = CKKSContext()
    mgr.create_context()
    print("\n✓ Created baseline CKKS context (poly_degree=8192)")

    # Add 100K support
    enc_counts = [1_000, 10_000, 100_000]
    print(f"\n[1/2] Running encryption benchmarks for {enc_counts}...")
    enc_res = encrypt_many(mgr, enc_counts, vector_len=1)

    mean_counts = [1_000, 10_000, 100_000]
    print(f"\n[2/2] Running mean calculation benchmarks for {mean_counts}...")
    mean_res = [(n, homomorphic_mean_time(mgr, n, vector_len=16)) for n in mean_counts]

    out = os.path.join("benchmarks", "ckks_baseline_results.csv")
    save_csv(out, enc_res, mean_res)
    
    print("\n" + "=" * 60)
    print("RESULTS:")
    print("=" * 60)
    for n, t in enc_res:
        print(f"encrypt records={n:>7,} time={t:>8.4f}s")
    for n, t in mean_res:
        print(f"mean    records={n:>7,} time={t:>8.4f}s ({t*1000:.1f}ms)")
    print(f"\n✓ Results saved to {out}")

