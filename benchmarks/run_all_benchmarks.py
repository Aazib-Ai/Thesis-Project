#!/usr/bin/env python
"""
SecureHealth Benchmark Runner
=============================

This script runs comprehensive benchmarks comparing Baseline CKKS vs Optimized AES-CKKS Hybrid
encryption for homomorphic computation on healthcare data.

Data Sources:
- Uses pre-generated synthetic patient data from data/synthetic/
- patients_1k.csv   (1,000 records)
- patients_10k.csv  (10,000 records)  
- patients_100k.csv (100,000 records)

Usage:
    python benchmarks/run_all_benchmarks.py

Custom Data:
    To use your own data, place CSV files in data/synthetic/ with the naming pattern:
    - your_data_1k.csv, your_data_10k.csv, your_data_100k.csv
    Then modify the DATA_FILES dictionary below.

Requirements:
    - Sufficient RAM (8GB+ recommended for 100K records)
    - For cloud deployment, ensure adequate compute resources
    - Benchmarks may take 10-30 minutes depending on hardware

Output:
    - benchmarks/ckks_baseline_results.csv
    - benchmarks/ckks_optimized_results.csv
"""

import os
import sys
import csv
import time
import random
from typing import List, Tuple, Dict
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ============================================================================
# CONFIGURATION - Modify these to use custom data
# ============================================================================

DATA_DIR = os.path.join("data", "synthetic")
OUTPUT_DIR = "benchmarks"

# Map record count to file name
DATA_FILES = {
    1000: "patients_1k.csv",
    10000: "patients_10k.csv",
    100000: "patients_100k.csv"
}

# Field to benchmark (must be numeric)
BENCHMARK_FIELD = "heart_rate"


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def print_header():
    """Print welcome banner"""
    print("\n" + "=" * 70)
    print("  SecureHealth - Homomorphic Encryption Benchmark Suite")
    print("  Comparing Baseline CKKS vs Optimized AES-CKKS Hybrid")
    print("=" * 70)
    print(f"\n  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def print_section(title: str):
    """Print section header"""
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def format_time(seconds: float) -> str:
    """Format seconds nicely"""
    if seconds >= 60:
        return f"{seconds / 60:.1f} min"
    elif seconds >= 1:
        return f"{seconds:.2f} sec"
    else:
        return f"{seconds * 1000:.1f} ms"


def format_number(n: int) -> str:
    """Format number with K/M suffix"""
    if n >= 1_000_000:
        return f"{n // 1_000_000}M"
    elif n >= 1_000:
        return f"{n // 1_000}K"
    return str(n)


def check_dependencies():
    """Check if required modules are installed"""
    missing = []
    
    try:
        import tenseal
    except ImportError:
        missing.append("tenseal")
    
    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing.append("pycryptodome")
    
    if missing:
        print("❌ Missing dependencies:")
        for m in missing:
            print(f"   - {m}")
        print("\n  Install them with:")
        print(f"     pip install {' '.join(missing)}")
        sys.exit(1)
    
    print("✓ All dependencies installed")


def check_data_files() -> Dict[int, str]:
    """Check if synthetic data files exist"""
    available = {}
    missing = []
    
    for count, filename in DATA_FILES.items():
        filepath = os.path.join(DATA_DIR, filename)
        if os.path.exists(filepath):
            available[count] = filepath
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            print(f"  ✓ {filename} ({size_mb:.1f} MB)")
        else:
            missing.append(filename)
            print(f"  ✗ {filename} (not found)")
    
    if not available:
        print("\n❌ No data files found!")
        print(f"   Expected location: {DATA_DIR}/")
        print("\n   You can generate synthetic data or place your own CSV files there.")
        sys.exit(1)
    
    if missing:
        print(f"\n⚠ Some files missing. Benchmarks will run on available data only.")
    
    return available


def load_field_values(filepath: str, field: str, limit: int = None) -> List[float]:
    """Load numeric values from a CSV field"""
    values = []
    with open(filepath, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            try:
                values.append(float(row[field]))
            except (ValueError, KeyError):
                continue
    return values


# ============================================================================
# BENCHMARK FUNCTIONS
# ============================================================================

def benchmark_ckks_encrypt(values: List[float], optimized: bool = False) -> float:
    """Benchmark CKKS encryption time"""
    from src.crypto.ckks_module import CKKSContext
    
    ctx = CKKSContext()
    if optimized:
        ctx.create_optimized_context()
    else:
        ctx.create_context()
    
    start = time.perf_counter()
    encrypted = [ctx.encrypt_vector([v]) for v in values]
    elapsed = time.perf_counter() - start
    
    return elapsed


def benchmark_ckks_mean(values: List[float], optimized: bool = False) -> float:
    """Benchmark CKKS homomorphic mean computation"""
    from src.crypto.ckks_module import CKKSContext
    from src.analytics.statistics import homomorphic_mean
    
    ctx = CKKSContext()
    if optimized:
        ctx.create_optimized_context()
    else:
        ctx.create_context()
    
    # First encrypt (not timed)
    encrypted = [ctx.encrypt_vector([v]) for v in values]
    
    # Time the mean computation
    start = time.perf_counter()
    result = homomorphic_mean(encrypted)
    decrypted = ctx.decrypt_vector(result)
    elapsed = time.perf_counter() - start
    
    return elapsed


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def run_benchmarks():
    """Run all benchmarks and save results"""
    print_header()
    
    # Pre-flight checks
    print_section("Checking Environment")
    check_dependencies()
    
    print_section("Checking Data Files")
    available_files = check_data_files()
    
    # Prepare output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    baseline_results = []
    optimized_results = []
    
    record_counts = sorted(available_files.keys())
    total_benchmarks = len(record_counts) * 4  # 2 operations x 2 versions
    current = 0
    
    print_section("Starting Benchmarks")
    print("\n  ⚠️  IMPORTANT NOTES:")
    print("  • Benchmarks process real encrypted data - this takes time!")
    print("  • 100K records may take 5-15 minutes depending on hardware")
    print("  • Ensure you have 8GB+ RAM available")
    print("  • For best results, close other applications")
    print("  • Cloud VMs with high CPU/RAM will perform better\n")
    
    input("  Press ENTER to start benchmarks (or Ctrl+C to cancel)...")
    
    overall_start = time.perf_counter()
    
    for count in record_counts:
        filepath = available_files[count]
        print(f"\n  📊 Loading {format_number(count)} records from {os.path.basename(filepath)}...")
        values = load_field_values(filepath, BENCHMARK_FIELD, limit=count)
        
        if len(values) < count:
            print(f"     ⚠ Only {len(values)} valid values found")
        
        # Baseline Encrypt
        current += 1
        print(f"\n  [{current}/{total_benchmarks}] CKKS Baseline - Encrypt ({format_number(count)} records)...")
        enc_time_base = benchmark_ckks_encrypt(values, optimized=False)
        print(f"       ✓ Completed in {format_time(enc_time_base)}")
        baseline_results.append(("encrypt", count, enc_time_base))
        
        # Optimized Encrypt
        current += 1
        print(f"  [{current}/{total_benchmarks}] CKKS Optimized - Encrypt ({format_number(count)} records)...")
        enc_time_opt = benchmark_ckks_encrypt(values, optimized=True)
        print(f"       ✓ Completed in {format_time(enc_time_opt)}")
        optimized_results.append(("encrypt", count, enc_time_opt))
        
        # Calculate speedup
        speedup = enc_time_base / enc_time_opt if enc_time_opt > 0 else 0
        print(f"       → Speedup: {speedup:.1f}x faster")
        
        # Baseline Mean
        current += 1
        print(f"\n  [{current}/{total_benchmarks}] CKKS Baseline - Mean ({format_number(count)} records)...")
        mean_time_base = benchmark_ckks_mean(values, optimized=False)
        print(f"       ✓ Completed in {format_time(mean_time_base)}")
        baseline_results.append(("mean", count, mean_time_base))
        
        # Optimized Mean
        current += 1
        print(f"  [{current}/{total_benchmarks}] CKKS Optimized - Mean ({format_number(count)} records)...")
        mean_time_opt = benchmark_ckks_mean(values, optimized=True)
        print(f"       ✓ Completed in {format_time(mean_time_opt)}")
        optimized_results.append(("mean", count, mean_time_opt))
        
        # Calculate speedup
        speedup = mean_time_base / mean_time_opt if mean_time_opt > 0 else 0
        print(f"       → Speedup: {speedup:.1f}x faster")
    
    overall_elapsed = time.perf_counter() - overall_start
    
    # Save results
    print_section("Saving Results")
    
    baseline_path = os.path.join(OUTPUT_DIR, "ckks_baseline_results.csv")
    with open(baseline_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "records", "seconds"])
        for metric, count, seconds in baseline_results:
            writer.writerow([metric, count, f"{seconds:.6f}"])
    print(f"  ✓ Saved: {baseline_path}")
    
    optimized_path = os.path.join(OUTPUT_DIR, "ckks_optimized_results.csv")
    with open(optimized_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "records", "seconds"])
        for metric, count, seconds in optimized_results:
            writer.writerow([metric, count, f"{seconds:.6f}"])
    print(f"  ✓ Saved: {optimized_path}")
    
    # Print summary
    print_section("Benchmark Summary")
    print(f"\n  Total time: {format_time(overall_elapsed)}")
    print(f"  Benchmarks completed: {current}")
    print(f"\n  Results saved to:")
    print(f"    • {baseline_path}")
    print(f"    • {optimized_path}")
    print(f"\n  View results at: http://127.0.0.1:5000/results")
    print(f"\n  Refresh the benchmark page to see updated charts!")
    
    # Summary table
    print("\n  Performance Comparison:")
    print("  " + "-" * 56)
    print(f"  {'Records':<10} {'Operation':<10} {'Baseline':<12} {'Optimized':<12} {'Speedup':<10}")
    print("  " + "-" * 56)
    
    for i in range(0, len(baseline_results)):
        metric, count, base_time = baseline_results[i]
        _, _, opt_time = optimized_results[i]
        speedup = base_time / opt_time if opt_time > 0 else 0
        print(f"  {format_number(count):<10} {metric:<10} {format_time(base_time):<12} {format_time(opt_time):<12} {speedup:.1f}x")
    
    print("  " + "-" * 56)
    print()


if __name__ == "__main__":
    try:
        run_benchmarks()
    except KeyboardInterrupt:
        print("\n\n  Benchmark cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
