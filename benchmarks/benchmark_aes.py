import csv
import os
import sys
import time
from typing import List, Tuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.crypto.aes_module import AESCipher


def run_benchmark(record_counts: List[int], plaintext_size: int = 128) -> List[Tuple[int, float, float]]:
    key = AESCipher.generate_key()
    results: List[Tuple[int, float, float]] = []

    for count in record_counts:
        plaintexts = [os.urandom(plaintext_size) for _ in range(count)]
        start = time.perf_counter()
        for pt in plaintexts:
            AESCipher.encrypt(pt, key)
        elapsed = time.perf_counter() - start
        throughput = count / elapsed if elapsed > 0 else 0.0
        results.append((count, elapsed, throughput))

    return results


def save_results_csv(results: List[Tuple[int, float, float]], path: str, plaintext_size: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["records", "plaintext_size_bytes", "total_seconds", "throughput_ops_per_sec"])
        for records, seconds, tput in results:
            w.writerow([records, plaintext_size, f"{seconds:.6f}", f"{tput:.2f}"])


if __name__ == "__main__":
    counts = [1_000, 10_000, 100_000]
    size = 128
    res = run_benchmark(counts, plaintext_size=size)
    save_results_csv(res, os.path.join("benchmarks", "aes_results.csv"), plaintext_size=size)
    for records, seconds, tput in res:
        print(f"records={records} size={size}B time={seconds:.4f}s throughput={tput:.2f} ops/s")
