# Yanluowang Ransomware

### NTDS Dump

#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND (sourceprocessname contains ntdsutil or destinationprocessname contains ntdsutil) AND (resourcecustomfield1 contains "ac i ntds")
```

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains ntdsutil or destinationprocessname contains ntdsutil) AND (resourcecustomfield1 contains "ac i ntds" or resourcecustomfield2 contains "ac i ntds")
```

#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains ntdsutil or destinationprocessname contains ntdsutil) AND (resourcecustomfield1 contains "ac i ntds" or resourcecustomfield2 contains "ac i ntds")
```

#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (sourceprocessname contains ntdsutil or destinationprocessname contains ntdsutil) AND (resourcecustomfield1 contains "ac i ntds" or resourcecustomfield2 contains "ac i ntds")
```

### Log Clearing

#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND (sourceprocessname contains wevtutil.exe or destinationprocessname contains wevtutil.exe) AND (resourcecustomfield1 contains "wevtutil.exe cl")
```

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains wevtutil.exe or destinationprocessname contains wevtutil.exe) AND (resourcecustomfield1 contains "wevtutil.exe cl" or resourcecustomfield2 contains "wevtutil.exe cl")
```

#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains wevtutil.exe or destinationprocessname contains wevtutil.exe) AND (resourcecustomfield1 contains "wevtutil.exe cl" or resourcecustomfield2 contains "wevtutil.exe cl")
```

#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains wevtutil.exe or destinationprocessname contains wevtutil.exe) AND (resourcecustomfield1 contains "wevtutil.exe cl" or resourcecustomfield2 contains "wevtutil.exe cl")
```

### Firewall Modification

#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND (resourcecustomfield1 contains "advfirewall" and resourcecustomfield1 contains "set rule group=remote" and resourcecustomfield1 contains "desktop new enable=Yes")
```

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND ((resourcecustomfield1 contains "advfirewall" and resourcecustomfield1 contains "set rule group=remote" and resourcecustomfield1 contains "desktop new enable=Yes") OR (resourcecustomfield2 contains "advfirewall" and resourcecustomfield2 contains "set rule group=remote" and resourcecustomfield2 contains "desktop new enable=Yes"))
```

#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND ((resourcecustomfield1 contains "advfirewall" and resourcecustomfield1 contains "set rule group=remote" and resourcecustomfield1 contains "desktop new enable=Yes") OR (resourcecustomfield2 contains "advfirewall" and resourcecustomfield2 contains "set rule group=remote" and resourcecustomfield2 contains "desktop new enable=Yes"))
```

#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND ((resourcecustomfield1 contains "advfirewall" and resourcecustomfield1 contains "set rule group=remote" and resourcecustomfield1 contains "desktop new enable=Yes") OR (resourcecustomfield2 contains "advfirewall" and resourcecustomfield2 contains "set rule group=remote" and resourcecustomfield2 contains "desktop new enable=Yes"))```
```

# TA558 Targets Hospitality and Travel firms

### Below queries looks for rare powershell commands execution which might lead to download of the AsyncRAT

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND (sourceprocessname = powershell.exe OR destinationprocessname = powershell.exe) AND (resourcecustomfield1 CONTAINS "http://" OR resourcecustomfield1 CONTAINS "https://") | RARE resourcecustomfield1

rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND resourcecustomfield1 CONTAINS "powershell -w h -NoProfile -ExecutionPolicy Bypass -
Command start-sleep -s 20;iwr" | RARE resourcecustomfield1
```

#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND (sourceprocessname = powershell.exe OR destinationprocessname = powershell.exe) AND (resourcecustomfield1 CONTAINS "http://" OR resourcecustomfield1 CONTAINS "https://") | RARE resourcecustomfield1

rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND resourcecustomfield1 CONTAINS "powershell -w h -NoProfile -ExecutionPolicy Bypass -
Command start-sleep -s 20;iwr" | RARE resourcecustomfield1
```

### Below queries detects persistence achieved by masquerading scheduled task services

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND resourcecustomfield1 CONTAINS "spotify" AND resourcecustomfield1 CONTAINS "schtasks /create /sc MINUTE /mo 1 0 /tn" AND resourcecustomfield1 CONTAINS "/tr"

rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND resourcecustomfield1 CONTAINS "schtasks /create /sc MINUTE /mo 1 /tn Turismo /F /tr"
```

#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND resourcecustomfield1 CONTAINS "spotify" AND resourcecustomfield1 CONTAINS "schtasks /create /sc MINUTE /mo 1 0 /tn" AND resourcecustomfield1 CONTAINS "/tr"

rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND resourcecustomfield1 CONTAINS "schtasks /create /sc MINUTE /mo 1 /tn Turismo /F /tr"
```

# Monster Libra leveraging IcedID with DarkVNC and Cobalt Strike

### Below queries detects suspicious scheduled task commandline for persistence

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND resourcecustomfield1 CONTAINS "rundll32.exe" AND resourcecustomfield1 CONTAINS "C:\Users\" AND resourcecustomfield1 CONTAINS "AppData\Roaming" AND (resourcecustomfield1 CONTAINS ".dll" OR resourcecustomfield1 CONTAINS ".dat" OR resourcecustomfield1 CONTAINS "LampEyebrow")
```

#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND resourcecustomfield1 CONTAINS "rundll32.exe" AND resourcecustomfield1 CONTAINS "C:\Users\" AND resourcecustomfield1 CONTAINS "AppData\Roaming" AND (resourcecustomfield1 CONTAINS ".dll" OR resourcecustomfield1 CONTAINS ".dat" OR resourcecustomfield1 CONTAINS "LampEyebrow")
```
