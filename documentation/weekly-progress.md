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

## Week 3: Further Development and Testing
October 17-23

**Completed:**
- Analyzed why the normal logs triggered 459 false alarms
- Found the main causes (system accounts, software installers, and updaters)
- Tested different tuning ideas before changing the rules
- Created 3 updated detection rules
- Ran Hayabusa again on both attack and normal logs
- Compared the results before and after tuning
- Checked that all 65 original true positives were still detected
- Made a pastel before-and-after comparison chart
- Investigated one attack sample and created an attack timeline

**Results so far:**
- Normal alerts decreased from 459 to 34
- Attack alerts decreased from 77 to 65
- False positives decreased from 467 to 34 (92.7% reduction)
- All 65 previously identified true positives were retained
- The 12 removed attack alerts included 8 false positives and 4 unclear alerts

**Challenges:**
- Some tuning ideas could remove real attack alerts, so I tested them first
- The Hayabusa output was missing some columns needed by my Python scripts
- The alert comparison showed mismatches because the PowerShell rule IDs were different
- Fixed the CSV output and checked the individual alerts to confirm the results

**Next week (Week 4):**
- Build a simple dashboard to show the results
- Write the 2-page final report
- Create the 5-slide presentation
- Review the project files and prepare the final output

## Week 4: Final Development and Presentation
October 24-30

**Completed so far:**
- Created an interactive dashboard using Streamlit and Plotly
- Used pastel pink and green charts to show the project results
- Added the false-positive reduction, true-positive counts, and alert comparisons
- Added an interactive chart showing the results of each detection rule
- Included the attack timeline in the dashboard
- Tested the dashboard on my Ubuntu VM
- Saved screenshots of the dashboard
- Uploaded the dashboard code and screenshots to GitHub
- Prepared the 5-slide PowerPoint presentation
- Wrote the 2-page project report
- Updated the README with the final results and dashboard instructions

**Final Results:**
- Normal alerts decreased from 459 to 34
- Attack alerts decreased from 77 to 65
- False positives decreased from 467 to 34 (92.7% reduction)
- All 65 previously identified true positives were retained
- Created a dashboard to display the results

**Challenges:**
- Had to learn how to use Streamlit and Plotly
- Some chart labels were hard to read, so I changed the text colors
- Adjusted the dashboard design to match my previous charts
- Had to shorten the project report to fit the 2-page requirement

**Remaining Tasks:**
- Review the final PowerPoint and project report
- Check the GitHub repository for missing files
- Prepare and submit the final requirements
