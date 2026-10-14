"""
Fill in true positive / false positive for the attack alerts, using simple rules.

Reads results/<stage>-attack-alerts-for-review.csv and results/<stage>-summary.csv,
writes results/<stage>-alert-classification.csv (every attack alert with a result and a reason)
and results/<stage>-classification-summary.csv (counts per rule).

How I decided (my own judgment, checked alert by alert):
- Alerts on the normal logs are false positives, because those logs come from clean systems.
- PowerShell Started: PowerShell inside an attack sample counts as part of the attack.
- Admin Logon: a real user account counts as part of the attack. A machine account (name ends
  with $) is normal background activity, except in the remote SAM sample, where it is unclear.
- Process From User Folder: a program started from a user folder counts as part of the attack,
  except normal OneDrive programs, which are false positives.

Run it from the repo folder:
    python3 scripts/classify_alerts.py before-tuning
"""
import csv
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

STRONG_POWERSHELL = ["-w hidden", "-nop", "downloadstring", "downloadfile", "bitstransfer", "printspoofer"]


def field(details, name):
    """Get one value from the details text, like 'Image' or 'User'."""
    for part in details.split("¦"):
        part = part.strip()
        if part.startswith(name + ":"):
            return part[len(name) + 1:].strip()
    return ""


def classify(row):
    rule, d = row["rule"], row["details"]
    if rule == "PowerShell Started":
        if any(s in d.lower() for s in STRONG_POWERSHELL):
            return "True Positive", "PowerShell with a suspicious option or behavior inside an attack sample"
        return "True Positive", f"PowerShell started inside a {row['sample_folder']} attack sample (no clear sign on its own)"

    if rule == "Admin Logon":
        user = field(d, "User")
        if user.endswith("$"):
            if "sam_registry" in row["sample_file"].lower():
                return "Unclear", "Machine account in a sample about backup privileges, could be part of the attack"
            return "False Positive", "Machine account logon, normal background activity"
        return "True Positive", "Logon by a real user account inside an attack sample"

    if rule == "Process From User Folder":
        image = field(d, "Image")
        if "\\onedrive\\" in image.lower():
            return "False Positive", "Normal OneDrive program running from the user folder"
        exe = image.split("\\")[-1] if image else "program"
        return "True Positive", f"{exe} started from a user folder inside a {row['sample_folder']} attack sample"

    return "Unclear", "No rule for this alert"


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "before-tuning"
    with open(RESULTS / f"{stage}-attack-alerts-for-review.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    for r in rows:
        r["result"], r["reason"] = classify(r)

    out = RESULTS / f"{stage}-alert-classification.csv"
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    counts = Counter((r["rule"], r["result"]) for r in rows)
    with open(RESULTS / f"{stage}-summary.csv", encoding="utf-8", newline="") as f:
        normal = {r["rule"]: int(r["normal_alerts"]) for r in csv.DictReader(f) if r["rule"] != "TOTAL"}

    rules = sorted(normal)
    print(f"\n=== {stage}: classification ===")
    print(f"{'Rule':<26}{'TP':>5}{'FP(att)':>9}{'Unclear':>9}{'FP(norm)':>10}{'FP total':>10}")
    summary_rows = []
    totals = [0, 0, 0, 0]
    for rule in rules:
        tp = counts[(rule, "True Positive")]
        fpa = counts[(rule, "False Positive")]
        un = counts[(rule, "Unclear")]
        fpn = normal[rule]
        print(f"{rule:<26}{tp:>5}{fpa:>9}{un:>9}{fpn:>10}{fpa + fpn:>10}")
        summary_rows.append([rule, tp, fpa, un, fpn, fpa + fpn])
        for i, v in enumerate([tp, fpa, un, fpn]):
            totals[i] += v
    print(f"{'TOTAL':<26}{totals[0]:>5}{totals[1]:>9}{totals[2]:>9}{totals[3]:>10}{totals[1] + totals[3]:>10}")

    with open(RESULTS / f"{stage}-classification-summary.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rule", "true_positives", "false_positives_attack_logs", "unclear",
                    "false_positives_normal_logs", "false_positives_total"])
        w.writerows(summary_rows)
        w.writerow(["TOTAL", totals[0], totals[1], totals[2], totals[3], totals[1] + totals[3]])
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
