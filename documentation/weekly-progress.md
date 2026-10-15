# Weekly Progress

## Week 1: Problem Identification & Research
October 1-8

**Completed:**
- Created my GitHub account and project repository
- Set up Git, SSH, VS Code, Python, and Hayabusa on my Ubuntu VM
- Wrote the project title, problem, objective, and scope
- Finished my research notes (Sigma, Hayabusa, false positives, existing solutions)
- Picked my first 3 detection rules and found possible sources for the attack logs

**Challenges:**
- Had some trouble with the Git and SSH setup
- Had to fix file names in my documentation folder
- Still deciding the source of my normal logs

**Next week (Week 2):**
- Decide and prepare the normal and attack logs
- Write the 3 Sigma rules
- Run Hayabusa and save the before-tuning results
- Start checking the alerts (true or false positive)
- Make a first basic chart

## Week 2: Design & Initial Development
October 10-16

**Completed:**
- Chose and downloaded my logs (attack: EVTX-ATTACK-SAMPLES, normal: evtx-baseline) and wrote logs/SOURCES.md
- Wrote 3 first-version rules (PowerShell Started, Admin Logon, Process From User Folder)
- Ran Hayabusa with my rules on both log sets and saved the before-tuning results
- Checked the 77 attack alerts (true or false positive)
- Made a first chart and a Python script that counts the alerts

**Results so far:**
- Before tuning: 77 alerts on the attack logs and 459 on the normal logs
- 65 true positives and 467 false positives (8 on attack logs, 459 on normal logs)

**Challenges:**
- The normal logs were a big separate download
- I could not test the failed logins rule, so I changed it to admin logons
- My chart showed the wrong severity at first, and I fixed my script

**Next week (Week 3):**
- Find out why the noisy alerts happened
- Tune the rules and run Hayabusa again
- Compare the results before and after
- Make one attack timeline
