# Week 3 Findings

## Goal

Reduce false alarms from normal activity without losing the real attack detections found in Week 2.

## Why False Alarms Happened

The first rules were too broad. They detected normal activities because they only checked basic event conditions.

### Admin Logon

There were 266 alerts from the normal logs.

Most came from:
- SYSTEM and other system accounts
- Desktop-related accounts
- Some normal user logons

The first rule alerted whenever a logon received special privileges, even when it was normal system activity.

### PowerShell Started

There were 5 alerts from the normal logs.

These came from normal software such as:
- Dropbox
- VS Code
- Office Setup32

The first rule alerted whenever PowerShell started, including when legitimate software used it.

### Process From User Folder

There were 188 alerts from the normal logs.

Many came from normal installers and updaters, including:
- Ninite
- SetUserFTA
- OneDrive
- Spotify and other software

The first rule alerted when programs ran from user-writable folders, even when the activity was normal.

## What I Changed

I created a second version of the three detection rules based on the false-positive patterns.

- **Admin Logon:** Filtered common system account SIDs.
- **PowerShell Started:** Filtered selected software parent processes.
- **Process From User Folder:** Filtered common installer and updater paths and parent processes.

I kept the original rules in `rules/v1-before-tuning` and saved the updated rules in `rules/v2-after-tuning`.

## Testing Method

I tested the tuned rules using the same two log sets from Week 2:

- Attack logs: 278 EVTX files
- Normal logs: 352 EVTX files

I used Hayabusa 4.1.0 to run the rules and generate the alerts.

After testing, I used Python scripts to count and classify the alerts. I also compared individual attack events before and after tuning.

## Before and After Results

| Metric | Before | After |
|---|---:|---:|
| Normal alerts | 459 | 34 |
| Attack alerts | 77 | 65 |
| True positives | 65 | 65 |
| False positives | 467 | 34 |
| Unclear | 4 | 0 |

**False-positive reduction: 92.7%**

The tuned rules removed 433 false positives from the tested logs.

All 65 previously identified true-positive events were retained.

The 12 removed attack alerts included:
- 8 false positives
- 4 unclear alerts
- 0 true positives

## Attack Timeline

I investigated `PanacheSysmon_vs_AtomicRedTeam01.evtx`.

The tuned rules detected four events:
- 3 PowerShell Started alerts
- 1 Process From User Folder alert

The events included a suspicious credential-related PowerShell command and a program running from a temporary folder.

The full event sequence is documented in `attack-timeline.md`.

## Limitations

The rules were tested only on the selected EVTX datasets.

Some excluded programs or accounts could still be used in attacks, so the filters may miss certain suspicious activities.

The true-positive classification was based on my review of the attack samples, not a complete list of all real attacks.

The results show improvement on these test logs, but do not guarantee detection of every future attack.

## Conclusion

The first version of the rules generated too many false alarms because the detection conditions were too broad.

After analyzing the alerts and tuning the rules, false positives decreased by 92.7%, while all 65 previously identified true positives were retained.

The updated rules produced fewer unnecessary alerts, making the results easier to review.
