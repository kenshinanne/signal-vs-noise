"""
Look for patterns in the false positives (the alerts on the normal logs).

Reads results/<stage>-normal.csv, groups the alerts of each rule by who or what caused them,
prints the groups, and saves the same text to results/<stage>-fp-patterns.txt.

Run it from the repo folder:
    python3 scripts/analyze_false_positives.py before-tuning
"""
import csv
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
lines = []


def emit(text=""):
    print(text)
    lines.append(text)


def field(details, name):
    """Get one value from the details text, like 'Image' or 'User'."""
    for part in details.split("¦"):
        part = part.strip()
        if part.startswith(name + ":"):
            return part[len(name) + 1:].strip()
    return ""


def clean_path(p):
    """Hide the user name inside C:\\Users\\<name>\\ so the same program groups together."""
    return re.sub(r"(?i)^([a-z]:\\users\\)[^\\]+", r"\1<USER>", p)


def is_system_account(user):
    u = user.upper()
    return u in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") or u.startswith(("DWM-", "UMFD-"))


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "before-tuning"
    with open(RESULTS / f"{stage}-normal.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    by_rule = {}
    for r in rows:
        by_rule.setdefault(r["RuleFile"], []).append(r["Details"])

    emit(f"=== {stage}: patterns in the {len(rows)} alerts on the normal logs ===")

    # Admin Logon
    d_list = by_rule.get("admin-logon.yml", [])
    emit(f"\n--- Admin Logon: {len(d_list)} alerts ---")
    users = Counter((field(d, "User"), field(d, "Domain")) for d in d_list)
    machine = sum(n for (u, _), n in users.items() if u.endswith("$"))
    system = sum(n for (u, _), n in users.items() if is_system_account(u))
    emit(f"Machine accounts (name ends with $): {machine}")
    emit(f"System accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-, UMFD-): {system}")
    emit(f"Other accounts: {len(d_list) - machine - system}")
    emit("Top accounts (count, user, domain):")
    for (u, dom), n in users.most_common(12):
        emit(f"  {n:>4}  {u}  |  {dom}")

    # Process From User Folder
    d_list = by_rule.get("user-folder-exec.yml", [])
    emit(f"\n--- Process From User Folder: {len(d_list)} alerts ---")
    images = Counter(clean_path(field(d, "Image")) for d in d_list)
    emit("Top programs (count, path):")
    for p, n in images.most_common(20):
        emit(f"  {n:>4}  {p[-95:]}")
    parents = Counter(clean_path(field(d, "Parent")).split("\\")[-1] or "(none)" for d in d_list)
    emit("Top parent programs (count, name):")
    for p, n in parents.most_common(8):
        emit(f"  {n:>4}  {p}")

    # PowerShell Started
    d_list = by_rule.get("ps-started.yml", [])
    emit(f"\n--- PowerShell Started: {len(d_list)} alerts ---")
    for d in d_list:
        emit(f"  {field(d, 'CommandLine')[:80]}  |  parent: {clean_path(field(d, 'Parent'))[-40:]}")

    out = RESULTS / f"{stage}-fp-patterns.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    emit(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
