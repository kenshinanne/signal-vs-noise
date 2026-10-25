# Signal vs. Noise
**Rule-Based Detection and False-Alarm Reduction in Security Log Monitoring**

**Project Area:** Security Operations & Detection Engineering

## Problem Statement
Security log monitoring can generate too many false alarms from normal activities. This makes it harder for security analysts to identify real threats.

## Objective
Create and test a small rule-based detection system that reduces false positives while keeping previously identified true positives.

## Tools Used
- Ubuntu (VirtualBox VM)
- Hayabusa 4.1.0
- Python
- Sigma-style YAML detection rules
- Matplotlib
- Streamlit and Plotly

## Datasets
- Attack logs: EVTX-ATTACK-SAMPLES (278 EVTX files)
- Normal logs: evtx-baseline (352 EVTX files)

The log files are not uploaded to this repository. Their sources are listed in `logs/SOURCES.md`.

## Detection Rules
I created three detection rules:

1. **PowerShell Started** - Detects PowerShell processes.
2. **Admin Logon** - Detects logons with special privileges.
3. **Process From User Folder** - Detects programs running from user-writable folders.

The original rules are in `rules/v1-before-tuning`.

The updated rules are in `rules/v2-after-tuning`.

## Methodology
1. Prepare the normal and attack logs.
2. Write and test the first version of the rules.
3. Run Hayabusa and save the alerts.
4. Classify the alerts as true positives, false positives, or unclear.
5. Analyze the causes of false alarms.
6. Tune the rules and test them again.
7. Compare the before-and-after results.
8. Show the results using charts and a dashboard.

## Final Results

| Metric | Before Tuning | After Tuning |
|---|---:|---:|
| Attack alerts | 77 | 65 |
| Normal alerts | 459 | 34 |
| True positives | 65 | 65 |
| False positives | 467 | 34 |
| Unclear | 4 | 0 |

**False-positive reduction: 92.7%**

The updated rules reduced false positives from 467 to 34 while keeping all 65 previously identified true positives in the tested logs.

![Before and After Results](screenshots/week3/before-after-chart.png)

## Dashboard

I created a simple interactive dashboard using Streamlit and Plotly.

The dashboard shows:
- False-positive reduction
- True positives retained
- Before-and-after alert comparison
- Alerts per detection rule
- An example attack timeline

### How to Run the Dashboard

Install the required tools:

```bash
python -m pip install -r dashboard/requirements.txt
```

Run the dashboard from the repository folder:

```bash
python -m streamlit run dashboard/app.py
```

Open `http://localhost:8501` in a browser.

## Limitations
- This project uses recorded Windows event logs, not real-time monitoring.
- The rules were only tested on selected public datasets.
- Alert classifications were based on my review.
- The tuned rules may still miss other suspicious activities.

## Project Status
- Week 1: Problem Identification & Research (done)
- Week 2: Design & Initial Development (done)
- Week 3: Further Development and Testing (done)
- Week 4: Final Dashboard and Submission (done)

## Ethics
All logs came from public datasets or authorized sources. No real systems were attacked.
