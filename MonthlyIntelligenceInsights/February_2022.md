# BlackByte Ransomware

### Endpoint Management Systems 

##### Please find the following search queries

```text
(rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched")) AND ((resourcecustomfield1 CONTAINS "FromBase64String(" AND resourcecustomfield1 CONTAINS "Stop-Service" AND resourcecustomfield1 CONTAINS "-Name") OR (destinationprocessname ENDS WITH "schtasks.exe" AND resourcecustomfield1 CONTAINS "/DELETE" AND resourcecustomfield1 CONTAINS "Raccine Rules Updater"))

rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched")) AND ((resourcecustomfield1 CONTAINS "vssadmin" AND resourcecustomfield1 CONTAINS "delete" AND resourcecustomfield1 CONTAINS "shadow") OR (resourcecustomfield1 CONTAINS "wbadmin" AND resourcecustomfield1 CONTAINS "delete" AND resourcecustomfield1 CONTAINS "catalog") OR (resourcecustomfield1 CONTAINS "wmic" AND resourcecustomfield1 CONTAINS "shadow" AND resourcecustomfield1 CONTAINS "delete") OR (resourcecustomfield1 CONTAINS "vssadmin" AND resourcecustomfield1 CONTAINS "resize" AND resourcecustomfield1 CONTAINS "shadowstorage"))

rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "netsh" AND resourcecustomfield1 CONTAINS "advfirewall" AND resourcecustomfield1 CONTAINS "firewall" AND resourcecustomfield1 CONTAINS "Network Discovery" AND resourcecustomfield1 CONTAINS "enable" AND resourcecustomfield1 CONTAINS "Yes"

rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "netsh" AND resourcecustomfield1 CONTAINS "advfirewall" AND resourcecustomfield1 CONTAINS "firewall" AND resourcecustomfield1 CONTAINS "File and Printer Sharing" AND resourcecustomfield1 CONTAINS "enable" AND resourcecustomfield1 CONTAINS "Yes"


rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "Microsoft\Windows\CurrentVersion\Policies\System" AND resourcecustomfield1 CONTAINS "LocalAccountTokenFilterPolicy"

rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "Microsoft\Windows\CurrentVersion\Policies\System" AND resourcecustomfield1 CONTAINS "EnableLinkedConnections"


rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "SYSTEM\CurrentControlSet\Control\FileSystem" AND resourcecustomfield1 CONTAINS "LongPathsEnabled"

rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "mountvol.exe" AND resourcecustomfield1 CONTAINS "Volume{"


rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "powershell.exe" AND resourcecustomfield1 CONTAINS "Install-WindowsFeature" AND resourcecustomfield1 CONTAINS "-Name" AND resourcecustomfield1 CONTAINS "RSAT-AD-PowerShell"

rg_functionality = "Endpoint Management Systems" AND (deviceaction ENDS WITH "Written" OR deviceaction = "File created") AND destinationprocessname ENDS WITH "MSExchangeMailboxReplication.exe" AND filename CONTAINS "\frontend\httpproxy\owa\auth\current\themes" AND filename ENDS WITH ".aspx"


rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "wuauclt.exe" AND (resourcecustomfield1 ENDS WITH "wuauclt.exe" OR resourcecustomfield1 ENDS WITH "wuauclt.exe"")


rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "cmd.exe" AND (resourcecustomfield1 CONTAINS "wordpad.exe" OR resourcecustomfield1 CONTAINS "notepad.exe") AND resourcecustomfield1 CONTAINS "/p"


```


# Lockbit 2.0 Ransomware

#### Damages built-in recovery and logging mechanisms

### Endpoint Management Systems

```text
rg_functionality = "Endpoint Management Systems" AND (resourcecustomfield1 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield2 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield3 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield1 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield2 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield3 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield1 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures" OR resourcecustomfield2 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures" OR resourcecustomfield3 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures")
```

### Antivirus / Malware / EDR

```text
rg_functionality = "Antivirus / Malware / EDR" AND (resourcecustomfield1 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield2 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield3 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield1 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield2 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield3 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield1 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures" OR resourcecustomfield2 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures" OR resourcecustomfield3 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures")
```

### Cloud Antivirus / Malware / EDR

```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (resourcecustomfield1 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield2 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield3 CONTAINS "cmd.exe /c vssadmin Delete Shadows /All /Quiet" OR resourcecustomfield1 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield2 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield3 CONTAINS "cmd.exe /c bcdedit /set {default} recoveryenabled No" OR resourcecustomfield1 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures" OR resourcecustomfield2 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures" OR resourcecustomfield3 CONTAINS "cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures")
```

##### Deletes itself and log data

### Endpoint Management Systems

```text
rg_functionality = "Endpoint Management Systems" AND (resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl application" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl application" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl application" OR (resourcecustomfield1 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield1 CONTAINS "Lsystem-234-bit.exe") OR (resourcecustomfield2 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield2 CONTAINS "Lsystem-234-bit.exe") OR (resourcecustomfield3 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield3 CONTAINS "Lsystem-234-bit.exe"))
```
### Antivirus / Malware / EDR

```text
rg_functionality = "Antivirus / Malware / EDR" AND (resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl application" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl application" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl application" OR (resourcecustomfield1 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield1 CONTAINS "Lsystem-234-bit.exe") OR (resourcecustomfield2 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield2 CONTAINS "Lsystem-234-bit.exe") OR (resourcecustomfield3 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield3 CONTAINS "Lsystem-234-bit.exe"))
```
### Cloud Antivirus / Malware / EDR

```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl security" OR resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl system" OR resourcecustomfield1 CONTAINS "cmd.exe /c wevtutil cl application" OR resourcecustomfield2 CONTAINS "cmd.exe /c wevtutil cl application" OR resourcecustomfield3 CONTAINS "cmd.exe /c wevtutil cl application" OR (resourcecustomfield1 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield1 CONTAINS "Lsystem-234-bit.exe") OR (resourcecustomfield2 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield2 CONTAINS "Lsystem-234-bit.exe") OR (resourcecustomfield3 CONTAINS "cmd.exe /c del /f /q" AND resourcecustomfield3 CONTAINS "Lsystem-234-bit.exe"))
```

# TrickBot

##### Remote Thread Creation Powershell Analytic

### Endpoint Management Systems

```text
rg_functionality = "Endpoint Management Systems" AND deviceaction = CreateRemoteThread detected AND (sourceprocessname ENDS WITH "powershell.exe" OR sourceprocessname ENDS WITH "powershell_ise.exe" OR sourceprocessname ENDS WITH "pwsh.exe") AND (destinationprocessname ENDS WITH "svchost.exe" OR destinationprocessname ENDS WITH "csrss.exe" OR destinationprocessname ENDS WITH "gpupdate.exe" OR destinationprocessname ENDS WITH "explorer.exe" OR destinationprocessname ENDS WITH "services.exe" OR destinationprocessname ENDS WITH "winlogon.exe" OR destinationprocessname ENDS WITH "smss.exe" OR destinationprocessname ENDS WITH "wininit.exe" OR destinationprocessname ENDS WITH "userinit.exe" OR destinationprocessname ENDS WITH "spoolsv.exe" OR destinationprocessname ENDS WITH "taskhost.exe")
```

### Antivirus / Malware / EDR

```text
rg_functionality = "Antivirus / Malware / EDR" AND deviceaction = CreateRemoteThread detected AND (sourceprocessname ENDS WITH "powershell.exe" OR sourceprocessname ENDS WITH "powershell_ise.exe" OR sourceprocessname ENDS WITH "pwsh.exe") AND (destinationprocessname ENDS WITH "svchost.exe" OR destinationprocessname ENDS WITH "csrss.exe" OR destinationprocessname ENDS WITH "gpupdate.exe" OR destinationprocessname ENDS WITH "explorer.exe" OR destinationprocessname ENDS WITH "services.exe" OR destinationprocessname ENDS WITH "winlogon.exe" OR destinationprocessname ENDS WITH "smss.exe" OR destinationprocessname ENDS WITH "wininit.exe" OR destinationprocessname ENDS WITH "userinit.exe" OR destinationprocessname ENDS WITH "spoolsv.exe" OR destinationprocessname ENDS WITH "taskhost.exe")

```
### Cloud Antivirus / Malware / EDR

```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND deviceaction = CreateRemoteThread detected AND (sourceprocessname ENDS WITH "powershell.exe" OR sourceprocessname ENDS WITH "powershell_ise.exe" OR sourceprocessname ENDS WITH "pwsh.exe") AND (destinationprocessname ENDS WITH "svchost.exe" OR destinationprocessname ENDS WITH "csrss.exe" OR destinationprocessname ENDS WITH "gpupdate.exe" OR destinationprocessname ENDS WITH "explorer.exe" OR destinationprocessname ENDS WITH "services.exe" OR destinationprocessname ENDS WITH "winlogon.exe" OR destinationprocessname ENDS WITH "smss.exe" OR destinationprocessname ENDS WITH "wininit.exe" OR destinationprocessname ENDS WITH "userinit.exe" OR destinationprocessname ENDS WITH "spoolsv.exe" OR destinationprocessname ENDS WITH "taskhost.exe")
```

##### Possible TrickBot Named Pipe Analytic

### Endpoint Management Systems

```text
rg_functionality = "Endpoint Management Systems" AND deviceaction CONTAINS pipe created AND (filename ENDS WITH lacesomepipe or filepath ENDS WITH lacesomepipe)
```

### Antivirus / Malware / EDR

```text
rg_functionality = "Antivirus / Malware / EDR" AND deviceaction CONTAINS pipe created AND (filename ENDS WITH lacesomepipe or filepath ENDS WITH lacesomepipe)

```

### Cloud Antivirus / Malware / EDR

```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND deviceaction CONTAINS pipe created AND (filename ENDS WITH lacesomepipe or filepath ENDS WITH lacesomepipe)
```

##### Potential Trickbot Execution Process Analytic

### Endpoint Management Systems

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND sourceprocessname ENDS WITH "OUTLOOK.EXE" AND destinationprocessname ENDS WITH "rundll32.exe" AND resourcecustomfield2 contains " -Embedding"

```

### Antivirus / Malware / EDR

```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND sourceprocessname ENDS WITH "OUTLOOK.EXE" AND destinationprocessname ENDS WITH "rundll32.exe" AND resourcecustomfield2 contains " -Embedding"
```
### Cloud Antivirus / Malware / EDR

```text

rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND sourceprocessname ENDS WITH "OUTLOOK.EXE" AND destinationprocessname ENDS WITH "rundll32.exe" AND resourcecustomfield2 contains " -Embedding"

```

Note: These queries in Silo may be prone to false positives and we recommend leveraging it with other stages of the attack progression to increase the likelihood of true positives
