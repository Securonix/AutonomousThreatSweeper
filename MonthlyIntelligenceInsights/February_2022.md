# BlackByte Ransomware

### Endpoint Management Systems 

#### This query detects any modification and/or disabling security tools to avoid possible detection of their malware/tools and activities

```text
(rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched")) AND ((resourcecustomfield1 CONTAINS "FromBase64String(" AND resourcecustomfield1 CONTAINS "Stop-Service" AND resourcecustomfield1 CONTAINS "-Name") OR (destinationprocessname ENDS WITH "schtasks.exe" AND resourcecustomfield1 CONTAINS "/DELETE" AND resourcecustomfield1 CONTAINS "Raccine Rules Updater"))
```

#### This query detects the possible deletion if the shadowcopies from the drives

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched")) AND ((resourcecustomfield1 CONTAINS "vssadmin" AND resourcecustomfield1 CONTAINS "delete" AND resourcecustomfield1 CONTAINS "shadow") OR (resourcecustomfield1 CONTAINS "wbadmin" AND resourcecustomfield1 CONTAINS "delete" AND resourcecustomfield1 CONTAINS "catalog") OR (resourcecustomfield1 CONTAINS "wmic" AND resourcecustomfield1 CONTAINS "shadow" AND resourcecustomfield1 CONTAINS "delete") OR (resourcecustomfield1 CONTAINS "vssadmin" AND resourcecustomfield1 CONTAINS "resize" AND resourcecustomfield1 CONTAINS "shadowstorage"))
```
#### This query detects modification of the firewall rules with netsh to enable the host to scan the network for discovery

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "netsh" AND resourcecustomfield1 CONTAINS "advfirewall" AND resourcecustomfield1 CONTAINS "firewall" AND resourcecustomfield1 CONTAINS "Network Discovery" AND resourcecustomfield1 CONTAINS "enable" AND resourcecustomfield1 CONTAINS "Yes"
```
#### This query detects modification of firewall with netsh command to allow the local file and printers to be discovered on the local network by other computers

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "netsh" AND resourcecustomfield1 CONTAINS "advfirewall" AND resourcecustomfield1 CONTAINS "firewall" AND resourcecustomfield1 CONTAINS "File and Printer Sharing" AND resourcecustomfield1 CONTAINS "enable" AND resourcecustomfield1 CONTAINS "Yes"
```
#### This query detects modification of LocalAccountTokenFilterPolicy registry key that can be used to disable UAC remote restrictions

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "Microsoft\Windows\CurrentVersion\Policies\System" AND resourcecustomfield1 CONTAINS "LocalAccountTokenFilterPolicy"
```
#### This query detects Malicious registry modifications by “EnableLinkedConnections” using “reg.exe

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "Microsoft\Windows\CurrentVersion\Policies\System" AND resourcecustomfield1 CONTAINS "EnableLinkedConnections"
```
#### This query detects Malicious registry modifications by enabling “LongPathsEnabled” within the Filesystem control

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "SYSTEM\CurrentControlSet\Control\FileSystem" AND resourcecustomfield1 CONTAINS "LongPathsEnabled"
```
#### This query detects for Malicious Driver Mount Process Creation using the process “mountvol.exe”

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "mountvol.exe" AND resourcecustomfield1 CONTAINS "Volume{"
```
#### This query detects installation of Active Directory RSAT tools, that allows you to perform basic operations with the AD directory

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "powershell.exe" AND resourcecustomfield1 CONTAINS "Install-WindowsFeature" AND resourcecustomfield1 CONTAINS "-Name" AND resourcecustomfield1 CONTAINS "RSAT-AD-PowerShell"
```
#### This query detects Microsoft Exchange Mailbox Replication service writing Active Server Pages

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction ENDS WITH "Written" OR deviceaction = "File created") AND destinationprocessname ENDS WITH "MSExchangeMailboxReplication.exe" AND filename CONTAINS "\frontend\httpproxy\owa\auth\current\themes" AND filename ENDS WITH ".aspx"
```
#### This query Detects parameterless use of processes Wuauclt.exe

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "wuauclt.exe" AND (resourcecustomfield1 ENDS WITH "wuauclt.exe" OR resourcecustomfield1 ENDS WITH "wuauclt.exe"")
```
#### This query Monitors for  Print bombing where the process “cmd” launches “wordpad” or “notepad” doc files and prints using “/p” command. Monitor for a spike in this activity.

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "cmd.exe" AND (resourcecustomfield1 CONTAINS "wordpad.exe" OR resourcecustomfield1 CONTAINS "notepad.exe") AND resourcecustomfield1 CONTAINS "/p"
```


# Lockbit 2.0 Ransomware

#### The following query detects deletion of the shadow copies using the commands below so that the victim cannot retrieve its data using built-in recovery services

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

##### This query detects the malware deletion and/or log data clearing


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
#### The following query looks for remote thread creation leveraging powershell in windows binaries so as to evade defense.

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

#### The following query looks for the pipe created event which enables communication with c2. 

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

#### The following query looks for rundll32.exe process creation from outlook.

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
