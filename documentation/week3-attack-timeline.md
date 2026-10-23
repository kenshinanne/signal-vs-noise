
# Week 3 Attack Timeline

## Sample Information

- File: PanacheSysmon_vs_AtomicRedTeam01.evtx
- Date: July 19, 2019 (UTC)
- Total detected alerts: 4
- Rules: PowerShell Started and Process From User Folder
- Source: results/after-tuning-attack.csv

## Timeline

### 1. PowerShell Started
Time: 14:43:03 UTC
RecordID: 3574
Rule: PowerShell Started

PowerShell was started through cmd.exe by IEUser.

This triggered the PowerShell rule, but starting PowerShell alone does not always mean an attack.

### 2. Suspicious PowerShell Command
Time: 14:46:51 UTC
RecordID: 3631
Rule: PowerShell Started

PowerShell ran a command using PromptForCredential with the title "Windows Security Update".

The command also tried to get the password from the entered credentials.

This is suspicious because it could be used to collect login information.

### 3. Program Running From Temp
Time: 14:57:04 UTC
RecordID: 4070
Rule: Process From User Folder

A program ran from the user's AppData\Local\Temp folder.

Its command included -decode and referenced file.exe and file.txt.

This triggered the User Folder rule because programs running from temporary folders can be suspicious.

### 4. PowerShell Started Again
Time: 15:09:59 UTC
RecordID: 4108
Rule: PowerShell Started

PowerShell started again through cmd.exe.

This was the last detected event in this sample.

## Findings

The tuned rules detected 4 events:
- 3 PowerShell Started alerts
- 1 Process From User Folder alert

The most suspicious activities were the credential-related PowerShell command and the program running from Temp.

This timeline only shows events detected by my rules. It does not prove that passwords were stolen or that the decode command succeeded.
