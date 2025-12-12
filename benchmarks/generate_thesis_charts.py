#!/usr/bin/env python
"""
Thesis-Ready Charts Generation Script
======================================
Generates publication-quality charts for thesis defense.
Exports in PNG (300 DPI), SVG, and PDF formats.

Charts Generated:
- H2: Accuracy vs Dataset Size
- H1: Data Segmentation Pie Chart
- H3: Performance vs Storage Trade-off
- H3: Memory Usage vs Dataset Size
- H3: End-to-End Latency Breakdown
- H4: Compliance Radar Chart
"""

import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib import rcParams
import seaborn as sns

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Publication-quality settings
rcParams['font.family'] = 'serif'
rcParams['font.serif'] = ['Times New Roman']
rcParams['font.size'] = 12
rcParams['axes.labelsize'] = 14
rcParams['axes.titlesize'] = 16
rcParams['xtick.labelsize'] = 11
rcParams['ytick.labelsize'] = 11
rcParams['legend.fontsize'] = 11
rcParams['figure.titlesize'] = 18
rcParams['figure.dpi'] = 300

# Professional color scheme
COLORS = {
    'primary': '#2E86AB',      # Deep blue
    'secondary': '#A23B72',    # Purple
    'accent': '#F18F01',       # Orange
    'success': '#06A77D',      # Green
    'danger': '#D90429',       # Red
    'warning': '#F77F00',      # Amber
    'aes': '#FF6B6B',          # Soft red for AES
    'ckks': '#4ECDC4',         # Teal for CKKS
    'hybrid': '#95E1D3',       # Light teal
    'baseline': '#FFA07A',     # Light salmon
}

OUTPUT_DIR = os.path.join("benchmarks", "charts", "thesis")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def save_chart(fig, name):
    """Save chart in PNG (300 DPI), SVG, and PDF formats."""
    base_path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(f"{base_path}.png", dpi=300, bbox_inches='tight', facecolor='white')
    fig.savefig(f"{base_path}.svg", format='svg', bbox_inches='tight')
    fig.savefig(f"{base_path}.pdf", format='pdf', bbox_inches='tight')
    print(f"✅ Saved {name} in PNG, SVG, PDF")


def chart_h2_accuracy_vs_dataset_size():
    """H2: Accuracy vs Dataset Size"""
    dataset_sizes = [1000, 10000, 100000]
    accuracy_mean = [99.999, 99.999, 99.999]
    accuracy_variance = [99.999, 99.998, 99.997]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(dataset_sizes))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, accuracy_mean, width, label='Mean Operation',
                   color=COLORS['primary'], alpha=0.9, edgecolor='black', linewidth=1.2)
    bars2 = ax.bar(x + width/2, accuracy_variance, width, label='Variance Operation',
                   color=COLORS['accent'], alpha=0.9, edgecolor='black', linewidth=1.2)
    
    # Add target line at 95%
    ax.axhline(y=95, color=COLORS['danger'], linestyle='--', linewidth=2, label='Target (95%)', alpha=0.7)
    
    ax.set_xlabel('Dataset Size (Records)', fontweight='bold')
    ax.set_ylabel('Accuracy (%)', fontweight='bold')
    ax.set_title('H2: Computational Accuracy vs Dataset Size', fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(['1,000', '10,000', '100,000'])
    ax.set_ylim([94.5, 100.2])
    ax.legend(loc='lower left', framealpha=0.95)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add value labels on bars
    def autolabel(bars):
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.3f}%',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    autolabel(bars1)
    autolabel(bars2)
    
    save_chart(fig, "h2_accuracy_vs_dataset_size")
    plt.close()


def chart_h1_data_segmentation_pie():
    """H1: Data Segmentation Pie Chart"""
    labels = ['PII (AES-256-GCM)', 'Vitals (CKKS)']
    sizes = [46.2, 53.8]
    colors = [COLORS['aes'], COLORS['ckks']]
    explode = (0.05, 0.05)
    
    fig, ax = plt.subplots(figsize=(10, 7))
    
    wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, colors=colors,
                                       autopct='%1.1f%%', shadow=True, startangle=90,
                                       textprops={'fontsize': 13, 'fontweight': 'bold'},
                                       wedgeprops={'edgecolor': 'black', 'linewidth': 2})
    
    # Enhance percentage text
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(14)
        autotext.set_fontweight('bold')
    
    ax.set_title('H1: Data Segmentation by Encryption Scheme', fontweight='bold', pad=20, fontsize=18)
    
    # Add legend with field counts
    legend_labels = [
        'PII Fields (6/13): patient_id, name, address, phone, email, dob',
        'Vitals (7/13): heart_rate, BP_sys, BP_dia, temp, glucose, BMI, cholesterol'
    ]
    ax.legend(legend_labels, loc='upper left', bbox_to_anchor=(0, -0.05), 
              frameon=True, fontsize=10, framealpha=0.95)
    
    save_chart(fig, "h1_data_segmentation_pie")
    plt.close()


def chart_h3_performance_vs_storage():
    """H3: Performance vs Storage Trade-off (Scatter Plot)"""
    # Data points: (Storage Expansion, Throughput ops/sec, Label)
    data_points = [
        (1.98, 39581, 'AES-256 (1K)', COLORS['aes']),
        (1.98, 36110, 'AES-256 (10K)', COLORS['aes']),
        (1.98, 27156, 'AES-256 (100K)', COLORS['aes']),
        (83524, 294, 'CKKS Baseline (1K)', COLORS['baseline']),
        (83524, 296, 'CKKS Baseline (10K)', COLORS['baseline']),
        (83524, 105, 'CKKS Optimized (1K)', COLORS['ckks']),
        (83524, 103, 'CKKS Optimized (10K)', COLORS['ckks']),
    ]
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    # Separate by scheme
    aes_data = [d for d in data_points if 'AES' in d[2]]
    ckks_base_data = [d for d in data_points if 'Baseline' in d[2]]
    ckks_opt_data = [d for d in data_points if 'Optimized' in d[2]]
    
    # Plot points
    for data_set, label, marker in [(aes_data, 'AES-256', 'o'), 
                                      (ckks_base_data, 'CKKS Baseline', 's'),
                                      (ckks_opt_data, 'CKKS Optimized', '^')]:
        x = [d[0] for d in data_set]
        y = [d[1] for d in data_set]
        colors = [d[3] for d in data_set]
        ax.scatter(x, y, s=200, c=colors, marker=marker, label=label, 
                  alpha=0.8, edgecolors='black', linewidths=1.5)
    
    ax.set_xlabel('Storage Expansion Factor (log scale)', fontweight='bold')
    ax.set_ylabel('Throughput (Operations/Second)', fontweight='bold')
    ax.set_title('H3: Performance vs Storage Trade-off', fontweight='bold', pad=20)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.legend(loc='best', framealpha=0.95)
    ax.grid(True, which="both", ls="--", alpha=0.3)
    
    # Add annotations
    ax.annotate('Low overhead,\nHigh performance', xy=(2, 35000), fontsize=11, 
               bbox=dict(boxstyle="round,pad=0.5", facecolor=COLORS['success'], alpha=0.3))
    ax.annotate('High overhead,\nHomomorphic capability', xy=(90000, 150), fontsize=11,
               bbox=dict(boxstyle="round,pad=0.5", facecolor=COLORS['warning'], alpha=0.3))
    
    save_chart(fig, "h3_performance_vs_storage")
    plt.close()


def chart_h3_memory_usage():
    """H3: Memory Usage vs Dataset Size"""
    dataset_sizes = [1000, 10000, 100000]
    baseline_memory = [245, 1850, 18200]
    optimized_memory = [198, 1520, 15100]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(dataset_sizes))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, baseline_memory, width, label='CKKS Baseline',
                   color=COLORS['baseline'], alpha=0.9, edgecolor='black', linewidth=1.2)
    bars2 = ax.bar(x + width/2, optimized_memory, width, label='Hybrid Optimized',
                   color=COLORS['ckks'], alpha=0.9, edgecolor='black', linewidth=1.2)
    
    ax.set_xlabel('Dataset Size (Records)', fontweight='bold')
    ax.set_ylabel('Memory Usage (MB)', fontweight='bold')
    ax.set_title('H3: Memory Usage Comparison', fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(['1,000', '10,000', '100,000'])
    ax.legend(loc='upper left', framealpha=0.95)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add reduction percentage labels
    for i, (b, o) in enumerate(zip(baseline_memory, optimized_memory)):
        reduction = ((b - o) / b) * 100
        ax.annotate(f'-{reduction:.1f}%',
                   xy=(i, max(b, o)),
                   xytext=(0, 5),
                   textcoords="offset points",
                   ha='center', va='bottom', fontsize=10, fontweight='bold',
                   color=COLORS['success'])
    
    save_chart(fig, "h3_memory_usage")
    plt.close()


def chart_h3_latency_breakdown():
    """H3: End-to-End Latency Breakdown (Stacked Bar)"""
    phases = ['Data\nClassification', 'AES\nEncryption\n(6 fields)', 'CKKS\nEncryption\n(7 fields)',
              'Network\nUpload', 'Server\nStorage']
    latencies = [12, 0.15, 23.8, 150, 45]
    
    colors_breakdown = [COLORS['primary'], COLORS['aes'], COLORS['ckks'], 
                       COLORS['warning'], COLORS['secondary']]
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    bottom = 0
    bars = []
    for i, (phase, latency, color) in enumerate(zip(phases, latencies, colors_breakdown)):
        bar = ax.barh(0, latency, left=bottom, height=0.6, 
                     color=color, edgecolor='black', linewidth=1.5, alpha=0.9)
        bars.append(bar)
        
        # Add percentage label
        percentage = (latency / sum(latencies)) * 100
        ax.text(bottom + latency/2, 0, f'{percentage:.1f}%\n{latency:.2f}ms', 
               ha='center', va='center', fontsize=11, fontweight='bold', color='white')
        
        bottom += latency
    
    ax.set_xlabel('Latency (milliseconds)', fontweight='bold')
    ax.set_title('H3: End-to-End Encryption Latency Breakdown', fontweight='bold', pad=20)
    ax.set_yticks([])
    ax.set_xlim([0, sum(latencies) * 1.05])
    
    # Create legend
    legend_elements = [mpatches.Patch(facecolor=color, edgecolor='black', label=phase.replace('\n', ' '))
                      for phase, color in zip(phases, colors_breakdown)]
    ax.legend(handles=legend_elements, loc='upper center', bbox_to_anchor=(0.5, -0.05),
             ncol=3, frameon=True, fontsize=10, framealpha=0.95)
    
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    
    # Total latency annotation
    ax.text(sum(latencies)/2, 0.35, f'Total: {sum(latencies):.2f}ms', 
           ha='center', va='bottom', fontsize=13, fontweight='bold',
           bbox=dict(boxstyle="round,pad=0.5", facecolor='yellow', alpha=0.5))
    
    save_chart(fig, "h3_latency_breakdown")
    plt.close()


def chart_h4_compliance_radar():
    """H4: Compliance Radar Chart"""
    categories = [
        'Data\nMinimization', 'Access\nControl', 'Audit\nLogging',
        'Encryption\nat Rest', 'Encryption\nin Transit', 'Right to\nErasure',
        'Data\nPortability', 'Purpose\nLimitation', 'Integrity &\nConfidentiality', 'Accountability'
    ]
    values = [100, 100, 100, 100, 100, 100, 90, 100, 100, 100]
    target = 95  # Target compliance percentage
    
    # Number of variables
    N = len(categories)
    
    # Compute angle for each axis
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    values += values[:1]  # Complete the circle
    angles += angles[:1]
    
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
    
    # Draw the area
    ax.plot(angles, values, 'o-', linewidth=2, color=COLORS['success'], label='Achieved')
    ax.fill(angles, values, alpha=0.25, color=COLORS['success'])
    
    # Draw target line
    target_values = [target] * (N + 1)
    ax.plot(angles, target_values, '--', linewidth=2, color=COLORS['danger'], 
           label=f'Target ({target}%)', alpha=0.7)
    
    # Fix axis to go in the right order
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylim(80, 105)
    ax.set_yticks([85, 90, 95, 100])
    ax.set_yticklabels(['85%', '90%', '95%', '100%'], fontsize=10)
    ax.set_title('H4: GDPR/HIPAA Compliance Radar Chart\nOverall Score: 99%', 
                fontweight='bold', pad=30, fontsize=16)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), framealpha=0.95)
    ax.grid(True, linestyle='--', alpha=0.5)
    
    save_chart(fig, "h4_compliance_radar")
    plt.close()


def chart_h2_mse_comparison():
    """H2: MSE Comparison (Supplementary)"""
    operations = ['Mean\n(1K)', 'Variance\n(1K)', 'Mean\n(10K)', 
                  'Variance\n(10K)', 'Mean\n(100K)', 'Variance\n(100K)']
    mse_values = [3.24e-10, 1.69e-08, 6.25e-10, 6.25e-08, 1.00e-08, 2.50e-07]
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    bars = ax.bar(operations, mse_values, color=COLORS['primary'], 
                  alpha=0.9, edgecolor='black', linewidth=1.2)
    
    ax.set_xlabel('Operation Type', fontweight='bold')
    ax.set_ylabel('Mean Squared Error (MSE)', fontweight='bold')
    ax.set_title('H2: Mean Squared Error Analysis', fontweight='bold', pad=20)
    ax.set_yscale('log')
    ax.grid(axis='y', alpha=0.3, linestyle='--', which='both')
    
    # Add value labels
    for bar, val in zip(bars, mse_values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
               f'{val:.2e}',
               ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    save_chart(fig, "h2_mse_comparison")
    plt.close()


def generate_all_thesis_charts():
    """Generate all thesis-ready charts."""
    print("\n" + "="*60)
    print("THESIS-READY CHARTS GENERATION")
    print("="*60)
    print(f"Output directory: {os.path.abspath(OUTPUT_DIR)}")
    print(f"Format: PNG (300 DPI), SVG, PDF\n")
    
    print("Generating charts...")
    
    chart_h2_accuracy_vs_dataset_size()
    chart_h2_mse_comparison()
    chart_h1_data_segmentation_pie()
    chart_h3_performance_vs_storage()
    chart_h3_memory_usage()
    chart_h3_latency_breakdown()
    chart_h4_compliance_radar()
    
    print("\n" + "="*60)
    print("✅ ALL CHARTS GENERATED SUCCESSFULLY")
    print("="*60)
    print(f"\nTotal charts: 7")
    print(f"Total files: 21 (7 charts × 3 formats)")
    print(f"\nLocation: {os.path.abspath(OUTPUT_DIR)}")


if __name__ == "__main__":
    generate_all_thesis_charts()
