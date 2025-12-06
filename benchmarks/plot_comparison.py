import os
import csv
import matplotlib.pyplot as plt


def load_csv(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def extract_mean_times(rows):
    out = {}
    for r in rows:
        if r["metric"] == "mean":
            out[int(r["records"])] = float(r["seconds"])
    return out


if __name__ == "__main__":
    base = os.path.join("benchmarks", "ckks_baseline_results.csv")
    opt = os.path.join("benchmarks", "ckks_optimized_results.csv")
    b = extract_mean_times(load_csv(base))
    o = extract_mean_times(load_csv(opt))
    records = sorted(set(b.keys()) | set(o.keys()))
    b_vals = [b[r] for r in records]
    o_vals = [o[r] for r in records]

    x = range(len(records))
    width = 0.35
    plt.figure(figsize=(8, 5))
    plt.bar([i - width / 2 for i in x], b_vals, width=width, label="Baseline")
    plt.bar([i + width / 2 for i in x], o_vals, width=width, label="Optimized")
    plt.xticks(list(x), [str(r) for r in records])
    plt.ylabel("Mean time (s)")
    plt.xlabel("Records")
    plt.title("CKKS Mean Calculation Time (Baseline vs Optimized)")
    plt.legend()
    outdir = os.path.join("benchmarks", "charts")
    os.makedirs(outdir, exist_ok=True)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "ckks_comparison.png"))

