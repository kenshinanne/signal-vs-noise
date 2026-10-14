"""
Summarize Hayabusa results (before or after tuning) for the Signal vs. Noise project.

Reads the attack and normal CSV files in results/, counts alerts per rule,
per severity, and per attack-sample folder, saves summary files, and draws a chart.

Run it from the repo folder:
    python3 scripts/summarize_results.py before-tuning
"""
import csv
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # draw to a file, no window needed
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
SHOTS = ROOT / "screenshots" / "week2"

# Chart colors (soft pastel, minimalist)
PINK = "#F4B6C2"
GREEN = "#B5DCC2"
TEXT = "#555555"
LIGHT = "#DDDDDD"

# Short, readable names for each rule file
RULE_NAMES = {
    "ps-started.yml": "PowerShell Started",
    "admin-logon.yml": "Admin Logon",
    "user-folder-exec.yml": "Process From\nUser Folder",
}
LEVEL_ORDER = ["informational", "low", "medium", "high", "critical", "emergency"]
# Hayabusa saves short level names in the CSV (like "med"), so turn them into full names
LEVEL_FULL = {"info": "informational", "low": "low", "med": "medium",
              "high": "high", "crit": "critical", "emer": "emergency"}


def read_rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def short_rule(row):
    return RULE_NAMES.get(row["RuleFile"], row["RuleTitle"])


def full_level(row):
    lvl = row["Level"].strip().lower()
    return LEVEL_FULL.get(lvl, lvl)


def sample_folder(evtx_path):
    """Folder name inside attack-samples, like 'Discovery' or 'Lateral Movement'."""
    parts = Path(evtx_path).parts
    if "attack-samples" in parts:
        i = parts.index("attack-samples")
        if len(parts) > i + 2:
            return parts[i + 1]
    return "(other)"


def style_axis(ax, title):
    """Minimalist look: no top/right lines, light grid, soft gray text."""
    ax.set_title(title, loc="left", fontsize=11, color=TEXT, pad=12)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(LIGHT)
    ax.tick_params(colors=TEXT, labelsize=9, length=0)
    ax.yaxis.grid(True, color="#EEEEEE", linewidth=0.8)
    ax.set_axisbelow(True)


def grouped_bars(ax, labels, a_vals, n_vals, title):
    x = list(range(len(labels)))
    w = 0.36
    b1 = ax.bar([i - w / 2 for i in x], a_vals, w, color=PINK, label="Attack logs")
    b2 = ax.bar([i + w / 2 for i in x], n_vals, w, color=GREEN, label="Normal logs")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.bar_label(b1, fontsize=8, color=TEXT, padding=2)
    ax.bar_label(b2, fontsize=8, color=TEXT, padding=2)
    style_axis(ax, title)


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "before-tuning"
    attack = read_rows(RESULTS / f"{stage}-attack.csv")
    normal = read_rows(RESULTS / f"{stage}-normal.csv")

    # 1) Alerts per rule
    a_rule = Counter(short_rule(r) for r in attack)
    n_rule = Counter(short_rule(r) for r in normal)
    rules = sorted(set(a_rule) | set(n_rule))

    print(f"\n=== {stage}: alerts per rule ===")
    print(f"{'Rule':<28}{'Attack':>8}{'Normal':>8}")
    for r in rules:
        print(f"{r.replace(chr(10), ' '):<28}{a_rule[r]:>8}{n_rule[r]:>8}")
    print(f"{'TOTAL':<28}{len(attack):>8}{len(normal):>8}")

    with open(RESULTS / f"{stage}-summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rule", "attack_alerts", "normal_alerts"])
        for r in rules:
            w.writerow([r.replace("\n", " "), a_rule[r], n_rule[r]])
        w.writerow(["TOTAL", len(attack), len(normal)])

    # 2) Alerts per severity
    a_lvl = Counter(full_level(r) for r in attack)
    n_lvl = Counter(full_level(r) for r in normal)
    levels = [l for l in LEVEL_ORDER if a_lvl[l] or n_lvl[l]]
    levels += sorted((set(a_lvl) | set(n_lvl)) - set(LEVEL_ORDER))  # keep any unexpected level too
    print(f"\n=== {stage}: alerts per severity ===")
    for l in levels:
        print(f"{l:<14}{a_lvl[l]:>8}{n_lvl[l]:>8}")

    # 3) Attack alerts per sample folder
    a_cat = Counter(sample_folder(r["EvtxFile"]) for r in attack)
    print(f"\n=== {stage}: attack alerts per sample folder ===")
    for k, v in a_cat.most_common():
        print(f"{k:<28}{v:>5}")
    with open(RESULTS / f"{stage}-attack-by-folder.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample_folder", "attack_alerts"])
        for k, v in a_cat.most_common():
            w.writerow([k, v])

    # 4) Chart: alerts per rule + alerts per severity
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.6))
    fig.patch.set_facecolor("white")
    grouped_bars(ax1, rules, [a_rule[r] for r in rules], [n_rule[r] for r in rules], "Alerts per rule")
    grouped_bars(ax2, levels, [a_lvl[l] for l in levels], [n_lvl[l] for l in levels], "Alerts per severity")
    ax1.set_ylabel("Number of alerts", color=TEXT, fontsize=9)
    ax1.legend(frameon=False, fontsize=9, labelcolor=TEXT)

    fig.suptitle(f"Signal vs. Noise  |  {stage.replace('-', ' ')}", fontsize=13, color=TEXT, x=0.06, ha="left")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    SHOTS.mkdir(parents=True, exist_ok=True)
    out = SHOTS / f"{stage}-chart.png"
    fig.savefig(out, dpi=150)
    print(f"\nChart saved: {out}")

    # 5) Review file for classifying the attack alerts (true or false positive)
    review = RESULTS / f"{stage}-attack-alerts-for-review.csv"
    with open(review, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "rule", "sample_folder", "sample_file", "details", "result", "reason"])
        rows = sorted(attack, key=lambda r: (short_rule(r), r["EvtxFile"], r["Timestamp"]))
        for i, r in enumerate(rows, 1):
            w.writerow([f"{i:03d}", short_rule(r).replace("\n", " "),
                        sample_folder(r["EvtxFile"]), Path(r["EvtxFile"]).name,
                        r["Details"], "", ""])
    print(f"Review file saved: {review} ({len(attack)} alerts)")


if __name__ == "__main__":
    main()
