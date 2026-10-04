## 2. Research: Sigma

Sigma is a way of writing detection rules. A detection rule tells a security tool what suspicious activity to look for in logs. Sigma rules are written in YAML, which is just a simple text format that is easy to read. A group called SigmaHQ shares a big collection of free Sigma rules online.

Sigma is useful because one rule can work with many different tools, so it doesn't have to be rewritten each time. The rules are also easy to read, and since there are already many free ones, we don't have to start from zero.

Here is a simple example I made to learn how a rule looks. It is not my final rule.

```yaml
title: Suspicious PowerShell Encoded Command
description: PowerShell running with an encoded command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
falsepositives:
    - Normal admin scripts
level: medium
```

The `logsource` says what kind of logs to check. The `detection` part has the conditions that make the rule raise an alert. The `falsepositives` part lists normal activity that could trigger the rule by mistake, and `level` is how serious the alert is.

Sigma can detect things like programs starting, PowerShell activity, and failed logins.

The problem is that free rules made by other people often cause too many false alarms in a different environment, so they need tuning. That is the main reason for my project.
