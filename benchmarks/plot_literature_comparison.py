import os
import csv
import matplotlib.pyplot as plt


def load(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


if __name__ == "__main__":
    path = os.path.join("benchmarks", "literature_comparison.csv")
    rows = load(path)
    fig, ax = plt.subplots(figsize=(9, 2 + 0.4 * len(rows)))
    ax.axis('off')
    table_data = [[r['Paper'], r['Year'], r['Mean_Calc_Time_ms'], r['Dataset_Size']] for r in rows]
    table = ax.table(cellText=table_data, colLabels=['Paper', 'Year', 'Mean Calc (ms)', 'Dataset Size'], loc='center')
    for (i, r) in enumerate(rows):
        if 'Our CKKS' in r['Paper']:
            for j in range(4):
                table[(i+1, j)].set_facecolor('#203255')
                table[(i+1, j)].set_edgecolor('#4ea3ff')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.5)
    outdir = os.path.join("benchmarks", "charts")
    os.makedirs(outdir, exist_ok=True)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "literature_comparison.png"))

