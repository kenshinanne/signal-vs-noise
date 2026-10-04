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

## Research C: False Positives

A false positive is an alert that looks suspicious to the system but is really normal activity. For example, a rule might alert every time PowerShell runs, but a normal admin also uses PowerShell for daily work.

A true positive is the opposite. It is an alert that correctly catches real suspicious activity.

**Why are false positives a problem?**

Analysts have to check every alert. If there are too many false ones, they waste time and get tired of alerts. This is called alert fatigue. When that happens, they might miss a real attack hidden between all the false alarms.

**Why do rules need tuning?**

Many rules are written to be broad, so they catch as much as possible. In a real environment, this also catches a lot of normal activity. Tuning means changing the rule to be more specific, so it makes fewer false alarms but still catches the real attack.

**Something to be careful about**

If a rule is tuned too much, it might stop catching real attacks. So after tuning, I need to test again and check that the real detections are still there.

**How this connects to my project**

My project will run some rules, count the false positives, tune the rules, run them again, and compare the results before and after.

## Research D: Existing Solutions

Companies have many computers, and each computer makes a lot of logs every day. It is too much for a person to read. So many companies use a tool called a SIEM to handle all the logs.

**What is a SIEM?**

SIEM stands for Security Information and Event Management. It takes the logs from all the computers and puts them in one place. Some examples are Splunk, Elastic Security, and Microsoft Sentinel. Wazuh is a free one.

**How does it work?**

A SIEM has detection rules. It checks the logs with these rules. When something matches a rule, it gives an alert. Then a security analyst looks at the alert and decides if it is a real attack or a false alarm. This is called alert triage. If it is real, the team looks into it more. If it is a false alarm, the analyst closes it. Sometimes they also change the rule so it does not happen again.

**Who does this work?**

The team that does this every day is called a SOC. This is the kind of job I want to do in the future.

**Other smaller tools**

There are also smaller tools that read logs without a full SIEM. Hayabusa and Chainsaw are two of them. They read Windows event logs and use Sigma rules to find suspicious things. Many people share Sigma rules for free, so we can use rules that others already made.

**What are the problems?**

These tools are very useful, but they also have problems. Some of them cost a lot and are hard to set up. The rules that come with them are usually made wide, so they give too many false alerts. Every company is different, so someone has to keep changing the rules to fit. If nobody does this, the analysts get too many alerts. They get tired and can miss the real ones.

**What can be better?**

One thing that can be better is making fewer false alerts without missing real attacks.

**How is my project different?**

My project is small and made for learning. It is not a full SIEM. It does not collect logs from many places, and it does not watch things in real time. I use free tools (Sigma rules and Hayabusa) to show the main idea. I run rules on logs, find the false alarms, change the rules, and check if it got better. I only focus on making fewer false alarms.
