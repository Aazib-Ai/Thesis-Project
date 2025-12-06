import os
import csv
import matplotlib.pyplot as plt


def load_kpis(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def pivot(rows, metric, system):
    out = {}
    for r in rows:
        if r["metric"] == metric and r["system"] == system:
            n = int(r["records"]) if r["records"] else 0
            out[n] = float(r["seconds"]) if r["seconds"] else 0.0
    return out


def pivot_throughput(rows, system):
    out = {}
    for r in rows:
        if r["metric"] == "throughput" and r["system"] == system:
            n = int(r["records"]) if r["records"] else 0
            out[n] = float(r["throughput_ops_per_sec"]) if r["throughput_ops_per_sec"] else 0.0
    return out


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


if __name__ == "__main__":
    kpi_path = os.path.join("benchmarks", "final_kpis.csv")
    rows = load_kpis(kpi_path)

    charts_dir = os.path.join("benchmarks", "charts")
    ensure_dir(charts_dir)

    # latency_comparison.png
    b_mean = pivot(rows, "mean_time", "CKKS_baseline")
    o_mean = pivot(rows, "mean_time", "CKKS_optimized")
    labels = sorted(set(b_mean.keys()) | set(o_mean.keys()))
    plt.figure(figsize=(8, 5))
    width = 0.35
    x = range(len(labels))
    plt.bar([i - width / 2 for i in x], [b_mean.get(n, 0) for n in labels], width=width, label="Baseline")
    plt.bar([i + width / 2 for i in x], [o_mean.get(n, 0) for n in labels], width=width, label="Optimized")
    plt.xticks(list(x), [str(n) for n in labels])
    plt.ylabel("Mean time (s)")
    plt.xlabel("Records")
    plt.title("CKKS Mean Calculation Time (Baseline vs Optimized)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "latency_comparison.png"))

    # throughput_scaling.png
    aes_tp = pivot_throughput(rows, "AES")
    plt.figure(figsize=(8, 5))
    nlabels = sorted(aes_tp.keys())
    plt.plot([str(n) for n in nlabels], [aes_tp[n] for n in nlabels], marker="o")
    plt.ylabel("Ops/sec")
    plt.xlabel("Records")
    plt.title("AES Throughput Scaling")
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "throughput_scaling.png"))

    # storage_expansion.png
    aes_exp = 0.0
    ckks_exp = 0.0
    for r in rows:
        if r["metric"] == "storage_expansion" and r["system"] == "AES":
            aes_exp = float(r["expansion_factor"]) if r["expansion_factor"] else 0.0
        if r["metric"] == "storage_expansion" and r["system"] == "CKKS":
            ckks_exp = float(r["expansion_factor"]) if r["expansion_factor"] else 0.0
    plt.figure(figsize=(6, 6))
    plt.pie([aes_exp, ckks_exp], labels=["AES", "CKKS"], autopct="%1.1f%%")
    plt.title("Storage Expansion (relative units)")
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, "storage_expansion.png"))

