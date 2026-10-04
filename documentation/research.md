## Research A: Sigma

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

## Research B: Hayabusa

Hayabusa is the tool I plan to use to run my detection rules. It was made by a group called Yamato Security in Japan. It reads Windows event logs, checks them against Sigma rules, and shows the suspicious events in a timeline.

**What logs does it read?**
Windows event logs (.evtx files). It can run on Linux, so I can use it on my Ubuntu VM, but the logs themselves are Windows logs.

**How does it use rules?**
It goes through the log events and checks each one against the Sigma rules. If an event matches a rule, it is written in the results with the rule name, time, and severity level.

**What does it output?**
A timeline of alerts as a CSV or JSON file. I can use this to count alerts, find false positives, and make my charts.

**Why I chose it**
It is easy to start with, and the results already include severity and time, which I need for my dashboard and attack timeline.

**Limits**
- It only reads Windows event logs, so I need Windows log samples.
- Its default rules produce many alerts, so I will use a small set of my own rules to keep my results clear.
- It finds suspicious events, but I still need to check each alert myself to see if it is real or a false positive.
