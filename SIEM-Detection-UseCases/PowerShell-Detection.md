# Suspicious PowerShell Detection

## Objective
Detect malicious PowerShell activity, especially encoded commands used by attackers.

---

## Attack Technique
Attackers often use encoded PowerShell commands to hide malicious intent:

Example:
powershell.exe -enc SQBtAHAAcwBvAHIAdAAgAG0AYQBsAHcAYQByAGUA

This uses Base64 encoding to evade detection.

---

## Detection Logic
- Monitor PowerShell execution
- Analyze command-line arguments
- Detect encoded commands (-enc, EncodedCommand)

---

## SIEM Detection Rule (Splunk)
index=windows 
(EventCode=4688 OR EventCode=4104)
| where Process_Name="powershell.exe"
| search CommandLine="* -enc *" OR CommandLine="*EncodedCommand*"

## Key Event IDs
- 4688: Process creation (tracks PowerShell execution)
- 4104: PowerShell script block logging (captures script content)

---

## Parent Process Insight
- Monitor PowerShell execution
- Analyze command-line arguments
- Detect encoded commands (-enc, EncodedCommand)
- Check parent processes (e.g., winword.exe, excel.exe, outlook.exe)

---

## MITRE ATT&CK Mapping
- T1059.001 – PowerShell

---

## Possible False Positives
- Legitimate admin scripts using encoded commands
- Automation tools

---

## Indicators of Suspicious Activity
- PowerShell spawned by Office applications
- Encoded commands with long Base64 strings
- Execution from user directories

---

## My Analysis
In real-world environments, attackers frequently use encoded PowerShell to bypass detection mechanisms. 
This detection helps identify such behavior early by focusing on command-line patterns.

---

## Improvements
- Decode Base64 commands automatically
- Correlate with parent processes (e.g., winword.exe, excel.exe)
- Alert on unusual execution patterns

---

## Real Scenario
This detection can identify phishing attacks where a malicious document spawns PowerShell in the background.

---

## Conclusion
Monitoring PowerShell command-line activity is critical for detecting fileless attacks and advanced threats.
