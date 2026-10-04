# Signal vs. Noise
**Rule-Based Detection and False-Alarm Reduction in Security Log Monitoring**

**Project Area:** Security Operations & Detection Engineering

## Problem Statement
Security log monitoring can generate many unnecessary alerts, making it harder for analysts to identify meaningful suspicious activity.

## Objective
Develop a small rule-based detection system that identifies suspicious activity in security logs, and reduce unnecessary alerts through rule tuning.

## Specific Goals
1. Collect or prepare normal and suspicious log data from authorized sources.
2. Write a small set of Sigma detection rules (suspicious PowerShell activity, multiple failed logins, suspicious process execution).
3. Run the rules with a detection tool (Hayabusa) and record the alerts.
4. Classify alerts as true positives or false positives.
5. Tune the rules, rerun them, and measure the before/after difference.
6. Present the results in a simple dashboard and an attack timeline.

## Scope
**In scope:** A small educational MVP using free, open-source tools on an Ubuntu VM; 3 starter detection rules; offline analysis of log files; before/after tuning results.

**Out of scope:** Real-time monitoring, production SIEM deployment, attacking any real system, and large-scale rule coverage.

## Workflow
Security Logs > Detection Rules > Detection Engine > Alerts > Alert Analysis > Rule Tuning > Results

## Ethics
All logs come from authorized public datasets or a controlled lab. No real systems are attacked.

## Status
Week 1 (Oct 1-8): Research and setup in PROGRESS.
