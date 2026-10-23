"""
Compare before and after tuning results.
Creates a pastel pink and green chart for Week 3.
"""

import csv
from pathlib import Path
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
SHOTS = ROOT / "screenshots" / "week3"

PINK = "#F4B6C2"
GREEN = "#B5DCC2"
TEXT = "#555555"
LIGHT = "#DDDDDD"


def get_total(stage, column):
    path = RESULTS / f"{stage}-summary.csv"
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["rule"] == "TOTAL":
                return int(row[column])
    raise ValueError(f"TOTAL missing in {path}")


def get_classification(stage):
    path = RESULTS / f"{stage}-classification-summary.csv"
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["rule"] == "TOTAL":
                return (
                    int(row["true_positives"]),
                    int(row["false_positives_total"]),
                    int(row["unclear"]),
                )
    raise ValueError(f"TOTAL missing in {path}")


def style(ax, title):
    ax.set_title(title, loc="left", fontsize=11, color=TEXT, pad=12)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(LIGHT)
    ax.tick_params(colors=TEXT, labelsize=9, length=0)
    ax.yaxis.grid(True, color="#EEEEEE", linewidth=0.8)
    ax.set_axisbelow(True)


def main():
    stages = ["before-tuning", "after-tuning"]
    normal = [get_total(s, "normal_alerts") for s in stages]
    attack = [get_total(s, "attack_alerts") for s in stages]
    classified = [get_classification(s) for s in stages]

    tp = [r[0] for r in classified]
    fp = [r[1] for r in classified]
    unclear = [r[2] for r in classified]

    labels = ["Before tuning", "After tuning"]
    x = [0, 1]
    width = 0.34

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.6))
    fig.patch.set_facecolor("white")

    # Left: number of alerts in each log set
    b1 = ax1.bar([i - width / 2 for i in x],
                 attack, width, color=PINK, label="Attack logs")
    b2 = ax1.bar([i + width / 2 for i in x],
                 normal, width, color=GREEN, label="Normal logs")

    ax1.set_xticks(x, labels)
    ax1.set_ylabel("Number of alerts", color=TEXT, fontsize=9)
    ax1.legend(frameon=False, fontsize=9, labelcolor=TEXT)
    ax1.bar_label(b1, padding=3, fontsize=9, color=TEXT)
    ax1.bar_label(b2, padding=3, fontsize=9, color=TEXT)
    style(ax1, "Alerts by log type")

    # Right: classification results
    b3 = ax2.bar([i - width / 2 for i in x],
                 fp, width, color=GREEN, label="False positives")
    b4 = ax2.bar([i + width / 2 for i in x],
                 tp, width, color=PINK, label="True positives")

    ax2.set_xticks(x, labels)
    ax2.legend(frameon=False, fontsize=9, labelcolor=TEXT)
    ax2.bar_label(b3, padding=3, fontsize=9, color=TEXT)
    ax2.bar_label(b4, padding=3, fontsize=9, color=TEXT)
    style(ax2, "Alert classification")

    fig.suptitle(
        "Signal vs. Noise  |  before vs. after tuning",
        fontsize=13, color=TEXT, x=0.06, ha="left"
    )
    fig.tight_layout(rect=(0, 0, 1, 0.94))

    SHOTS.mkdir(parents=True, exist_ok=True)
    out = SHOTS / "before-after-chart.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)

    reduction = (fp[0] - fp[1]) / fp[0] * 100

    print("\n=== BEFORE VS. AFTER ===")
    print(f"Normal alerts: {normal[0]} -> {normal[1]}")
    print(f"Attack alerts: {attack[0]} -> {attack[1]}")
    print(f"True positives: {tp[0]} -> {tp[1]}")
    print(f"False positives: {fp[0]} -> {fp[1]}")
    print(f"Unclear: {unclear[0]} -> {unclear[1]}")
    print(f"False-positive reduction: {reduction:.1f}%")
    print(f"\nChart saved: {out}")


if __name__ == "__main__":
    main()
