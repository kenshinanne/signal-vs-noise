# Methodology

## Workflow
```
Security Logs
      v
Detection Rules
      v
Detection Engine (Hayabusa)
      v
Alerts
      v
Alert Analysis
      v
Rule Tuning
      v
Results
```

## Steps
1. Prepare the logs (done in Week 2)
2. Write the rules (version 1 done in Week 2)
3. Run the detection and save the before-tuning results (done in Week 2)
4. Check the alerts as true or false positives (done for the attack logs in Week 2)
5. Tune the rules that give too many false alerts (Week 3)
6. Run it again and save the after-tuning results (Week 3)
7. Compare before and after (Week 3)
8. Show the results in a dashboard and an attack timeline (Weeks 3 and 4)

## Logs
- Attack logs: EVTX-ATTACK-SAMPLES, 278 files
- Normal logs: evtx-baseline, Logs_Client folder, 352 files
- The log files are not in this repo. The sources are in logs/SOURCES.md.

## Rules (version 1)
1. PowerShell Started: any PowerShell process start
2. Admin Logon: any logon with special privileges
3. Process From User Folder: a program started from a user-writable folder

The rules are in rules/v1-before-tuning. They are broad on purpose. In Week 3, I will change them based on the false positives I find. Hayabusa does not use the logsource part of a rule, so my rules write the log name and event ID in the detection part.

## How I measure results
I count these numbers before and after tuning:
- Total alerts
- False positives
- True positives (relevant detections)
- How much the false positives went down

All numbers come from my own runs. A Python script (scripts/summarize_results.py) counts the alerts and makes the chart. Another script (scripts/classify_alerts.py) applies my true/false positive decisions.

## Scope and safety
- I only analyze recorded logs. I do not attack any real system.
- This is a small learning project. It is not a full SIEM, and it does not watch logs in real time.

## Limits
- Hayabusa only reads Windows event logs.
- The normal logs come from one or two machines over about two days.
- I count all alerts on the normal logs as false positives, because they come from clean systems.
- I labeled the attack alerts myself, so some labels could be wrong.

## Plan for the next weeks
- **Week 3 (Oct 17-23):** find out why each noisy alert happened, tune the rules, run again, compare before and after, and make one attack timeline.
- **Week 4 (Oct 24-30):** final testing, final dashboard, clean GitHub, 2-page report, and 5-slide presentation. Oct 31 is for a last check.
