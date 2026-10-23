"""
Test tuning ideas BEFORE changing the rules.

For each idea, this shows how many alerts on the normal logs would go away (less noise)
and how many true positives on the attack logs would be lost (a real detection missed).
Reads the before-tuning results and saves the text to results/<stage>-tuning-tests.txt.

Run it from the repo folder:
    python3 scripts/test_tuning_ideas.py before-tuning
"""
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from classify_alerts import classify, field, STRONG_POWERSHELL  # my true/false positive decisions

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RULES = {
    "ps-started.yml": "PowerShell Started",
    "admin-logon.yml": "Admin Logon",
    "user-folder-exec.yml": "Process From User Folder",
}
lines = []


def emit(text=""):
    print(text)
    lines.append(text)


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def sample_folder(evtx_path):
    parts = Path(evtx_path).parts
    if "attack-samples" in parts:
        i = parts.index("attack-samples")
        if len(parts) > i + 2:
            return parts[i + 1]
    return "(other)"


def label(r):
    row = {"rule": RULES[r["RuleFile"]], "details": r["Details"],
           "sample_file": Path(r["EvtxFile"]).name, "sample_folder": sample_folder(r["EvtxFile"])}
    return classify(row)[0]


# Small helpers that read one value from an alert
def img(r):
    return field(r["Details"], "Image").lower()


def parent_name(r):
    return field(r["Details"], "Parent").replace("/", "\\").split("\\")[-1].lower()


def sid(r):
    return field(r["ExtraFieldInfo"], "SubjectUserSid")


# Each idea says when the tuned rule would NOT alert (skip = True)
IDEAS = {
    "admin-logon.yml": [
        ("A1 skip system accounts (SID S-1-5-18/19/20, DWM, UMFD)",
         lambda r: sid(r) in ("S-1-5-18", "S-1-5-19", "S-1-5-20") or sid(r).startswith(("S-1-5-90-", "S-1-5-96-"))),
    ],
    "user-folder-exec.yml": [
        ("B1 skip the Windows Defender platform folder",
         lambda r: "\\programdata\\microsoft\\windows defender\\" in img(r)),
        ("B2 skip OneDrive, Spotify, Foxit, Google Update folders",
         lambda r: any(x in img(r) for x in ("\\appdata\\local\\microsoft\\onedrive\\", "\\appdata\\roaming\\spotify\\",
                                             "\\foxit software\\", "\\google\\temp\\"))),
        ("B3 skip Inno Setup installer folders (Temp\\is-*.tmp)",
         lambda r: re.search(r"\\temp\\is-[^\\]+\.tmp\\", img(r)) is not None),
        ("B4 skip Opera installer folders",
         lambda r: "\\.opera\\" in img(r) or "opera installer temp" in img(r)),
        ("B5 skip programs started by Ninite.exe or target.tmp",
         lambda r: parent_name(r) in ("ninite.exe", "target.tmp")),
    ],
    "ps-started.yml": [
        ("P1 skip parents Dropbox.exe, Code.exe, Setup32.exe",
         lambda r: parent_name(r) in ("dropbox.exe", "code.exe", "setup32.exe")),
        ("P2 only alert on suspicious command-line options",
         lambda r: not any(s in r["Details"].lower() for s in STRONG_POWERSHELL)),
    ],
}


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "before-tuning"
    attack = read(RESULTS / f"{stage}-attack.csv")
    normal = read(RESULTS / f"{stage}-normal.csv")
    for r in attack:
        r["label"] = label(r)

    emit(f"=== {stage}: testing tuning ideas ===")
    emit("normal removed = false alarms that go away | TP lost = real detections that would be missed")

    for rf, rule in RULES.items():
        n = [r for r in normal if r["RuleFile"] == rf]
        a = [r for r in attack if r["RuleFile"] == rf]
        tp = [r for r in a if r["label"] == "True Positive"]
        fp = [r for r in a if r["label"] == "False Positive"]
        un = [r for r in a if r["label"] == "Unclear"]
        emit(f"\n--- {rule}: normal {len(n)} | attack {len(a)} (TP {len(tp)}, FP {len(fp)}, unclear {len(un)}) ---")
        emit(f"{'idea':<58}{'normal removed':>15}{'TP lost':>9}{'FP removed':>11}{'unclear':>8}")
        safe = []
        for name, skip in IDEAS[rf]:
            lost = sum(1 for r in tp if skip(r))
            emit(f"{name:<58}{sum(1 for r in n if skip(r)):>9} of {len(n):<3}{lost:>5}/{len(tp):<3}"
                 f"{sum(1 for r in fp if skip(r)):>6}/{len(fp):<4}{sum(1 for r in un if skip(r)):>4}/{len(un)}")
            if lost == 0:
                safe.append(skip)
        if len(IDEAS[rf]) > 1 and safe:
            both = lambda r, s=safe: any(f(r) for f in s)
            emit(f"{'COMBINED (all ideas that lose no true positives)':<58}{sum(1 for r in n if both(r)):>9} of {len(n):<3}"
                 f"{sum(1 for r in tp if both(r)):>5}/{len(tp):<3}{sum(1 for r in fp if both(r)):>6}/{len(fp):<4}"
                 f"{sum(1 for r in un if both(r)):>4}/{len(un)}")

    out = RESULTS / f"{stage}-tuning-tests.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    emit(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
