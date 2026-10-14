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


def full_level(row):
    lvl = row["Level"].strip().lower()
    return LEVEL_FULL.get(lvl, lvl)


def read_rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def short_rule(row):
    return RULE_NAMES.get(row["RuleFile"], row["RuleTitle"])


def sample_folder(evtx_path):
    """Folder name inside attack-samples, like 'Discovery' or 'Lateral Movement'."""
    parts = Path(evtx_path).parts
    if "attack-samples" in parts:
        i = parts.index("attack-samples")
        if len(parts) > i + 2:
            return parts[i + 1]
    return "(other)"


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
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    x = range(len(rules))
    w = 0.38
    b1 = ax1.bar([i - w / 2 for i in x], [a_rule[r] for r in rules], w, label="Attack logs")
    b2 = ax1.bar([i + w / 2 for i in x], [n_rule[r] for r in rules], w, label="Normal logs")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(rules, fontsize=9)
    ax1.set_ylabel("Number of alerts")
    ax1.set_title("Alerts per rule")
    ax1.bar_label(b1, fontsize=8)
    ax1.bar_label(b2, fontsize=8)
    ax1.legend(fontsize=8)

    xl = range(len(levels))
    c1 = ax2.bar([i - w / 2 for i in xl], [a_lvl[l] for l in levels], w, label="Attack logs")
    c2 = ax2.bar([i + w / 2 for i in xl], [n_lvl[l] for l in levels], w, label="Normal logs")
    ax2.set_xticks(list(xl))
    ax2.set_xticklabels(levels, fontsize=9)
    ax2.set_title("Alerts per severity")
    ax2.bar_label(c1, fontsize=8)
    ax2.bar_label(c2, fontsize=8)

    fig.suptitle(f"Signal vs. Noise: {stage.replace('-', ' ')} results", fontsize=12)
    fig.tight_layout()
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
