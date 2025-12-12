#!/usr/bin/env python
"""
Accuracy Charts Generator
=========================
Generates visualization charts for Phase 1 H2:
1. MSE vs Dataset Size
2. Accuracy Percentage by Operation
3. Error Distribution Histogram
"""

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Setup paths
METRICS_FILE = os.path.join("benchmarks", "accuracy_metrics.csv")
DISTRIBUTION_FILE = os.path.join("benchmarks", "error_distribution.csv")
CHARTS_DIR = os.path.join("benchmarks", "charts")

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def plot_mse_vs_size(df):
    """Chart 1: MSE vs Dataset Size (Line Chart)"""
    plt.figure(figsize=(10, 6))
    
    # Filter for mean/variance
    # df has: operation, record_count, mse...
    
    sns.set_style("whitegrid")
    sns.lineplot(data=df, x="record_count", y="mse", hue="operation", marker="o", linewidth=2.5)
    
    plt.xscale("log")
    plt.yscale("log") # MSE varies by orders of magnitude usually
    plt.title("MSE vs Dataset Size (Log-Log Scale)", fontsize=14)
    plt.xlabel("Number of Records", fontsize=12)
    plt.ylabel("Mean Squared Error (MSE)", fontsize=12)
    plt.tight_layout()
    
    out_path = os.path.join(CHARTS_DIR, "accuracy_mse.png")
    plt.savefig(out_path, dpi=300)
    print(f"Saved {out_path}")
    plt.close()

def plot_accuracy_percentage(df):
    """Chart 2: Accuracy Percentage vs Target (Bar Chart)"""
    plt.figure(figsize=(8, 6))
    
    # We want to show if we meet 99.99% target
    # Simplify: Take the worst case (min accuracy) or show all?
    # Let's show max accuracy per operation for the largest dataset? 
    # Or just bar plot of all datapoints?
    
    # Group by operation and take mean or min accuracy?
    # Let's just plot all points as a bar chart grouped by count
    
    sns.barplot(data=df, x="record_count", y="accuracy_pct", hue="operation")
    
    # Add target line
    plt.axhline(y=99.99, color='r', linestyle='--', label='Target (99.99%)')
    
    plt.ylim(99.0, 100.05) # Zoom in to show high accuracy details
    plt.title("Accuracy Percentage by Operation & Size", fontsize=14)
    plt.xlabel("Dataset Size", fontsize=12)
    plt.ylabel("Accuracy (%)", fontsize=12)
    plt.legend(loc='lower right')
    plt.tight_layout()
    
    out_path = os.path.join(CHARTS_DIR, "accuracy_percentage.png")
    plt.savefig(out_path, dpi=300)
    print(f"Saved {out_path}")
    plt.close()

def plot_error_distribution(df):
    """Chart 3: Error Distribution (Histogram)"""
    plt.figure(figsize=(10, 6))
    
    # df has "Absolute Error" column
    # Use log scale for x axis if errors vary widely? 
    # Or simple histogram.
    
    sns.histplot(df["Absolute Error"], bins=50, kde=True, color="purple")
    
    plt.title("Absolute Error Distribution (Sample N=1000)", fontsize=14)
    plt.xlabel("Absolute Error", fontsize=12)
    plt.ylabel("Frequency", fontsize=12)
    plt.tight_layout()
    
    out_path = os.path.join(CHARTS_DIR, "error_distribution.png")
    plt.savefig(out_path, dpi=300)
    print(f"Saved {out_path}")
    plt.close()

def generate_charts():
    ensure_dir(CHARTS_DIR)
    
    # Load Metrics
    if os.path.exists(METRICS_FILE):
        df_metrics = pd.read_csv(METRICS_FILE)
        plot_mse_vs_size(df_metrics)
        plot_accuracy_percentage(df_metrics)
    else:
        print(f"Warning: {METRICS_FILE} not found. Skipping metrics charts.")
        
    # Load Distribution
    if os.path.exists(DISTRIBUTION_FILE):
        df_dist = pd.read_csv(DISTRIBUTION_FILE)
        plot_error_distribution(df_dist)
    else:
        print(f"Warning: {DISTRIBUTION_FILE} not found. Skipping distribution chart.")

if __name__ == "__main__":
    generate_charts()
