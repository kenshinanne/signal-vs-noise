# Methodology

## Workflow
```
Security Logs
      v
Detection Rules (Sigma)
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

## Steps I Plan to Follow

1. **Prepare the logs.**

   I will keep normal logs and attack logs in separate folders. I will write down where each log came from and what it is.
   
3. **Write the rules.**

   I will write a small number of Sigma rules that I understand.
   
5. **Run the detection.**
   
   I will use Hayabusa to check the logs with my rules and save the alerts. This is my "before tuning" result.
   
7. **Check the alerts.**
   
   I will look at each alert and decide if it is a true positive or a false positive, and write the reason.
   
9. **Tune the rules.**
    
    I will change the rules that give too many false alerts so they are more exact.
   
11. **Run it again.**
    
    I will save the new alerts as my "after tuning" result.
  
13. **Compare.**
    
    I will compare the before and after numbers.
    
15. **Show the results.**
    
    I will make a simple dashboard and an attack timeline.

## First Detection Rules (planned)
1. Suspicious PowerShell activity
2. Multiple failed login attempts
3. Suspicious process execution

I will write these in Week 2.

## Logs (planned)
- **Attack logs:** public Windows event log samples made for testing detection tools.
- **Normal logs:** I am still deciding the source. I will not upload logs that have personal information.
- I will write down the source and type of every log file.

## How I Will Measure Results
I will count these numbers before and after tuning:
- Total alerts
- False positives
- Relevant detections (true positives)
- How much the false positives went down

I will only use real numbers from my own tests.

## Scope and Safety
- I only analyze recorded logs. I do not attack any real system.
- This is a small learning project. It is not a full SIEM, and it does not watch logs in real time.

## Limits
- Hayabusa only reads Windows event logs.
- Public sample logs may not look like logs from a real company.
- I have to check each alert myself.
