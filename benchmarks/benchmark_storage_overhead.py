#!/usr/bin/env python
"""
Storage Overhead Benchmark

Measures ciphertext expansion factors for the hybrid encryption system
to quantify cloud storage costs.

Metrics:
- AES expansion factor (expected: ~1.1x)
- CKKS expansion factor (expected: ~100-200x)
- Hybrid overall expansion
- Storage savings vs pure CKKS

Output:
- benchmarks/storage_overhead_results.csv
- benchmarks/charts/storage_comparison.png
"""

import os
import sys
import csv
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analytics.storage_metrics import (
    calculate_expansion_factor,
    measure_aes_ciphertext_size,
    measure_ckks_ciphertext_size,
    compare_storage_overhead
)

# Configuration
DATA_DIR = os.path.join("data", "synthetic")
OUTPUT_DIR = "benchmarks"
CHARTS_DIR = os.path.join(OUTPUT_DIR, "charts")

DATASET_SIZES = {
    "1K": 1000,
    "10K": 10000,
    "100K": 100000
}


def measure_csv_file_size(filepath: str) -> int:
    """Get file size in bytes"""
    if os.path.exists(filepath):
        return os.path.getsize(filepath)
    return 0


def benchmark_storage_overhead():
    """Run storage overhead benchmarks"""
    print("\n" + "=" * 70)
    print("  Storage Overhead Benchmark")
    print("=" * 70)
    
    results = []
    
    for label, num_records in DATASET_SIZES.items():
        print(f"\n📊 Analyzing {label} records...")
        
        # Get CSV file size (if available)
        csv_filename = f"patients_{label.lower()}.csv"
        csv_filepath = os.path.join(DATA_DIR, csv_filename)
        csv_size = measure_csv_file_size(csv_filepath)
        
        if csv_size == 0:
            print(f"   ⚠ {csv_filename} not found, using estimated size")
            # Estimate: ~360 bytes per record (9 fields × ~40 bytes avg)
            csv_size = num_records * 360
        
        print(f"   Plaintext CSV size: {csv_size / 1024:.2f} KB")
        
        # Compare storage overhead
        analysis = compare_storage_overhead(
            num_records=num_records,
            pii_fields=6,  # patient_id, name, address, phone, email, dob
            analytics_fields=3,  # heart_rate, blood_pressure_systolic, blood_pressure_diastolic
            avg_pii_size=50  # Average PII field size in bytes
        )
        
        # Store results
        results.append({
            "dataset": label,
            "num_records": num_records,
            "plaintext_kb": csv_size / 1024,
            "pure_ckks_mb": analysis["pure_ckks_size"] / 1024 / 1024,
            "hybrid_mb": analysis["hybrid_size"] / 1024 / 1024,
            "aes_expansion": analysis["aes_expansion"],
            "ckks_expansion": analysis["ckks_expansion"],
            "pure_ckks_expansion": analysis["pure_ckks_expansion"],
            "hybrid_expansion": analysis["hybrid_expansion"],
            "storage_savings_pct": analysis["storage_savings_pct"]
        })
        
        print(f"   Pure CKKS: {analysis['pure_ckks_size'] / 1024 / 1024:.2f} MB ({analysis['pure_ckks_expansion']:.1f}x)")
        print(f"   Hybrid: {analysis['hybrid_size'] / 1024 / 1024:.2f} MB ({analysis['hybrid_expansion']:.1f}x)")
        print(f"   ✅ Storage savings: {analysis['storage_savings_pct']:.1f}%")
    
    # Save results to CSV
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results_path = os.path.join(OUTPUT_DIR, "storage_overhead_results.csv")
    
    with open(results_path, 'w', newline='') as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    
    print(f"\n✅ Results saved to: {results_path}")
    
    # Generate chart
    generate_storage_chart(results)
    
    return results


def generate_storage_chart(results):
    """Generate storage comparison chart"""
    print("\n📊 Generating storage comparison chart...")
    
    df = pd.DataFrame(results)
    
    # Create figure with subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Chart 1: Storage Size Comparison
    x = range(len(df))
    width = 0.35
    
    ax1.bar([i - width/2 for i in x], df["pure_ckks_mb"], width, 
            label='Pure CKKS', color='#e74c3c', alpha=0.8)
    ax1.bar([i + width/2 for i in x], df["hybrid_mb"], width,
            label='Hybrid (Optimized)', color='#27ae60', alpha=0.8)
    
    ax1.set_xlabel('Dataset Size', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Storage Size (MB)', fontsize=12, fontweight='bold')
    ax1.set_title('Cloud Storage Requirements', fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(df["dataset"])
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)
    
    # Chart 2: Expansion Factors
    ax2.bar([i - width/2 for i in x], df["pure_ckks_expansion"], width,
            label='Pure CKKS', color='#e74c3c', alpha=0.8)
    ax2.bar([i + width/2 for i in x], df["hybrid_expansion"], width,
            label='Hybrid (Optimized)', color='#27ae60', alpha=0.8)
    
    ax2.set_xlabel('Dataset Size', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Expansion Factor (×)', fontsize=12, fontweight='bold')
    ax2.set_title('Ciphertext Expansion Factor', fontsize=14, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(df["dataset"])
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    
    # Save chart
    os.makedirs(CHARTS_DIR, exist_ok=True)
    chart_path = os.path.join(CHARTS_DIR, "storage_comparison.png")
    plt.savefig(chart_path, dpi=300, bbox_inches='tight')
    print(f"✅ Chart saved to: {chart_path}")
    
    plt.close()


def print_summary(results):
    """Print benchmark summary"""
    print("\n" + "=" * 70)
    print("  Storage Overhead Summary")
    print("=" * 70)
    
    print(f"\n{'Dataset':<10} {'Plaintext':<12} {'Pure CKKS':<15} {'Hybrid':<15} {'Savings':<10}")
    print("-" * 70)
    
    for r in results:
        print(f"{r['dataset']:<10} {r['plaintext_kb']:<11.2f}KB "
              f"{r['pure_ckks_mb']:<14.2f}MB {r['hybrid_mb']:<14.2f}MB "
              f"{r['storage_savings_pct']:<9.1f}%")
    
    # Overall statistics
    avg_savings = sum(r['storage_savings_pct'] for r in results) / len(results)
    print("-" * 70)
    print(f"\n  Average storage savings (Hybrid vs Pure CKKS): {avg_savings:.1f}%")
    print(f"  AES expansion factor: {results[0]['aes_expansion']:.2f}x")
    print(f"  CKKS expansion factor: {results[0]['ckks_expansion']:.1f}x")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    try:
        results = benchmark_storage_overhead()
        print_summary(results)
        print("\n✅ Storage overhead benchmark completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
