#!/usr/bin/env python
"""
Sample Data Comparison Generator
================================
Generates a comparison table of Plaintext vs Encrypted/Decrypted values 
to demonstrate accuracy at a granular level.
"""

import os
import sys
import csv
import pandas as pd
import numpy as np
from typing import List, Dict

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto.ckks_module import CKKSContext

# Configuration
DATA_FILE = os.path.join("data", "synthetic", "patients_1k.csv")
OUTPUT_CSV = os.path.join("benchmarks", "sample_data_comparison.csv")
OUTPUT_MD = os.path.join("benchmarks", "sample_data_comparison.md")
SAMPLE_SIZE = 1000 # Increased for distribution chart
TABLE_SIZE = 20
FIELD = "heart_rate"
DISTRIBUTION_CSV = os.path.join("benchmarks", "error_distribution.csv")

def generate_sample_comparison():
    print(f"Generating Sample Comparison for {FIELD}...")
    
    # Check data
    if not os.path.exists(DATA_FILE):
        print(f"Error: Data file {DATA_FILE} not found.")
        return

    # Load Sample
    df = pd.read_csv(DATA_FILE)
    sample = df.head(SAMPLE_SIZE).copy()
    
    # Initialize Crypto
    print("Initializing CKKS context...")
    ctx = CKKSContext()
    ctx.create_optimized_context() # Using optimized context
    
    results = []
    
    print(f"Processing {SAMPLE_SIZE} records...")
    for idx, row in sample.iterrows():
        plaintext_val = float(row[FIELD])
        
        # Encrypt
        enc = ctx.encrypt_vector([plaintext_val])
        
        # specific hex preview (just first few chars of serialized)
        try:
            if idx < TABLE_SIZE:
                serialized = enc.serialize()
                hex_preview = serialized.hex()[:16] + "..."
            else:
                hex_preview = ""
        except:
            hex_preview = "N/A"
            
        # Decrypt
        dec_list = enc.decrypt()
        decrypted_val = dec_list[0]
        
        # Calculate Error
        abs_error = abs(plaintext_val - decrypted_val)
        rel_error_pct = (abs_error / abs(plaintext_val)) * 100 if plaintext_val != 0 else 0
        
        results.append({
            "Record": idx + 1,
            "Plaintext HR": plaintext_val,
            #"Encrypted": hex_preview, 
            "Decrypted HR": decrypted_val,
            "Absolute Error": abs_error,
            "Relative Error (%)": f"{rel_error_pct:.7f}%"
        })

    # Create DataFrame
    res_df = pd.DataFrame(results)
    
    # Save full distribution
    res_df[["Record", "Plaintext HR", "Decrypted HR", "Absolute Error"]].to_csv(DISTRIBUTION_CSV, index=False)
    print(f"Saved Distribution CSV to {DISTRIBUTION_CSV} ({len(res_df)} records)")
    
    # Table (Top 20)
    table_df = res_df.head(TABLE_SIZE).copy()
    
    # Save CSV
    table_df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved Sample CSV to {OUTPUT_CSV}")
    
    # Generate Markdown Table
    try:
        md_table = table_df.to_markdown(index=False, tablefmt="github")
    except ImportError:
        print("Warning: tabulate not installed. Using string format fallback.")
        md_table = table_df.to_string(index=False)
    
    with open(OUTPUT_MD, "w") as f:
        f.write(f"# Sample Data Comparison - {FIELD}\n\n")
        f.write(f"Generated from: `{os.path.basename(DATA_FILE)}`\n\n")
        f.write(md_table)
        f.write("\n")
        
    print(f"Saved Markdown to {OUTPUT_MD}")
    print("\nPreview:")
    print(md_table)

if __name__ == "__main__":
    generate_sample_comparison()
