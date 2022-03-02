# Pro-Ukraine Conti Release

### Next Generation Firewall & Firewwall
```text
index=activity AND rg_functionality="Next Generation Firewall" AND ipaddress NOT NULL AND ipaddress IN ("138.124.180.94", "45.14.226.47", "193.203.203.101")
index=activity AND rg_functionality="Firewall" AND ipaddress NOT NULL AND ipaddress IN ("138.124.180.94", "45.14.226.47", "193.203.203.101")
```
### Web Proxy
```text
index=activity AND rg_functionality="Web Proxy" AND ipaddress NOT NULL AND ipaddress IN ("138.124.180.94", "45.14.226.47", "193.203.203.101")
```
### Web Application Firewall
```text
index=activity AND rg_functionality="Web Application Firewall" AND ipaddress NOT NULL AND ipaddress IN ("138.124.180.94", "45.14.226.47", "193.203.203.101")
```
### DNS / DHCP
```text
index=activity AND rg_functionality="DNS / DHCP" AND ipaddress NOT NULL AND ipaddress IN ("138.124.180.94", "45.14.226.47", "193.203.203.101")
```
### IDS / IPS / UTM / Threat Detection
```text 
index=activity AND rg_functionality="IDS / IPS / UTM / Threat Detection" AND ipaddress NOT NULL AND ipaddress IN ("138.124.180.94", "45.14.226.47", "193.203.203.101")
```



| Attacker Group | Functionality | Policy Name | Signature ID |
|--------------- | ------------- | ----------- | ------------ |
| Russian Ops | Web Server | Possible CVE-2019-11510 Exploitation Attempt Analytic | WEB-ALL-815-RU |
| Russian Ops | Web Server | Possible CVE-2021–26855 Exploitation Attempt Suspicious Username Analytic | WEB-ALL-813-RU |
| (Gamaredon, Primitive Bear, ACTINIUM, Shuckworm, Pterodo) | Endpoint Management Systems | Potential Pterodo Backdoor CommandLine Analytic | EDR-ALL-336-RU |
| (Gamaredon, Primitive Bear, ACTINIUM, Shuckworm) | Endpoint Management Systems | Suspicious Scheduled Task Process Creation Analytic | EDR-ALL-335-RU |
| (Gamaredon, Primitive Bear, ACTINIUM, Shuckworm) | Endpoint Management Systems | Potential VNC Client CommandLine Analytic | EDR-ALL-334-RU |
| HermeticWiper | Endpoint Management Systems | Potential Malicious Activity CrashDump Disabled Registry Analytic | EDR-ALL-333-RU |
| BlackByte | Endpoint Management Systems | Potential Print Bombing Attempt CommandLine Analytic | EDR-ALL-907-RU |
| BlackByte | Endpoint Management Systems | Possible ProxyShell Exploitation Attempt File Creation Analytic | EDR-ALL-909-RU |
| BlackByte | Endpoint Management Systems | Disabled UAC Remote Restrictions CommandLine Analytic | EDR-ALL-910-RU |
| BlackByte | Endpoint Management Systems | Installation Of Active Directory RSAT Tools Process Creation Analytic | EDR-ALL-911-RU |
| BlackByte | Endpoint Management Systems | Potential Malicious Driver Mount Process Creation Analytic | EDR-ALL-912-RU |
| BlackByte | Endpoint Management Systems | Potential Malicious Registry Modifications CommandLine Analytic | EDR-ALL-913-RU |
| BlackByte | Endpoint Management Systems | Potential Malicious Firewall Rules Modification CommandLine Analytic | EDR-ALL-914-RU |
| BlackByte | Endpoint Management Systems | Potential Critical Windows Services Modification Attempt CommandLine Analytic | EDR-ALL-915-RU |
| BlackByte | Endpoint Management Systems | Potential Malicious Mapped Drives Modifications CommandLine Analytic | EDR-ALL-916-RU |

# MuddyWater 

### Endpoint Management Systems 

#### Monitor for the following rare processes being executed:gram_app.exe, index.ex

```text
rg_functionality = "Endpoint Management Systems" and (sourceprocessname ="gram_app.exe" or destinationprocessname ="gram_app.exe" or sourceprocessname ="index.exe" or destinationprocessname ="index.exe")
```
#### Monitor for the following rare files / DLLs being created:Cooperation terms.xls, FML.dll, MicrosoftWindowsOutlookDataPlus.txt 

```text
rg_functionality = "Endpoint Management Systems" and (filename = "Cooperation terms.xls" or filename ="FML.dll" or filename = "MicrosoftWindowsOutlookDataPlus.txt")
```
#### Monitor for persistence with any modifications to the  current user startup folder: file path contains \Windows\Start Menu\Programs\Startup 

```text
rg_functionality = "Endpoint Management Systems" and filepath CONTAINS "\Windows\Start Menu\Programs\Startup" and filename ends with ".wsf"
```
#### Monitor for rare registry modifications : HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OutlookMicrosoft

```text
rg_functionality = "Endpoint Management Systems" and devicecustomstring2 CONTAINS "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OutlookMicrosift"
```

# Hermetic Wiper 

### Endpoint Management Systems

#### Monitor for Registry key changes to disable crash dumps (CrashDumpEnabled = 0) from the path "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl"

```text
"rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND resourcecustomfield1 CONTAINS ""HKLM\SYSTEM\CurrentControlSet\Control\CrashControl"" AND  resourcecustomfield1 CONTAINS  ""CrashDumpEnabled"" AND  resourcecustomfield1 CONTAINS ""0""
```

#### Monitor for Rare registry key changes to diable ShowCompColor, ShowInfoTip  from the path "\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

```text
rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND resourcecustomfield1 CONTAINS ""Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"" AND (resourcecustomfield1 CONTAINS ShowCompColor OR resourcecustomfield1 CONTAINS ShowInfoTip) AND resourcecustomfield1 CONTAINS ""0""
```

#### Monitor for rare files created and/or executed from known windows system folders

```text
rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND resourcecustomfield1 CONTAINS ""C:\Windows\system32\Drivers"" | Rare resourcecustomfield1
```

#### Monitor for rare commands executed to identify the operating system version

```text 
rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND (resourcecustomfield1 CONTAINS ""VerSetConditionMask"" OR resourcecustomfield1 CONTAINS ""VerifyVersionInfoW"")
```

#### Monitor for Rare processes spawned from command prompt

```text
rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND sourceprocessname contains ""cmd.exe"" and resourcecustomfield1 contains expand

rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") and resourcecustomfield1 contains EPMNTDRV
```
#### Monitor for rare sys files created on system folders (Eg: %WINDIR%\system32\driver\<random_2chars>dr.sys)

```text
rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND resourcecustomfield1 contains ""C:\Windows\system32\"" and resourcecustomfield1 contains ""dr.sys"""
```

### Microsoft Windows

#### Monitor for Rare privilege escalation attempts by acccounts within the ADFS

```text
rg_functionality=""microsoft windows"" and (baseeventid=4672 OR baseeventid=4673 OR baseeventid=4674) and sourceuserprivileges IN(SeShutDownPrivilege,SeBackupPrivilege,SeLoadDriverPrivilege) | Rare accountname
```
#### Monitor for Rare processes spawned from command prompt

```text 
rg_functionality=""microsoft windows"" and baseeventid=4688 and sourceprocessname=cmd.exe and destinationprocessname =expand.exe
rg_functionality = windows and baseeventid=4688 and baseeventid=4663 and sourceprocessname contains EPMNTDRV or destinationprocessname contains EPMNTDRV
```

# Cyclops Blink 

### Unix / Linux / AIX

#### Monitor rare command line parameters for the process kworker

```text
rg_functionality = "Unix / Linux / AIX" AND (sourceprocessname CONTAINS "kworker" OR deviceprocessname CONTAINS "kworker" ) | RARE devicecustomstring1

rg_functionality = "Unix / Linux / AIX" AND (sourceprocessname CONTAINS "kworker" OR deviceprocessname CONTAINS "kworker") AND  ((devicecustomstring1 CONTAINS "execl" AND devicecustomstring1 CONTAINS "/proc/self/exe") OR (customstring2 CONTAINS "execl" AND customstring2 CONTAINS "/proc/self/exe"))
```

### Next Generation Firewall & Firewall

#### Monitor for C2 communication on HTTP & HTTPS protocols on non-standard ports

```text
rg_functionality = "Next Generation firewall" AND (applicationprotocol = HTTP OR applicationprotocol = HTTPS) AND destinationport != 443 AND destinationport != 80

rg_functionality = "Firewall" AND (applicationprotocol = HTTP OR applicationprotocol = HTTPS) AND destinationport != 443 AND destinationport != 80
```
#### Monitor for exfiltration to C2 server over covert channels such as SSH, TELNET, RDP, DNS.

```text
rg_functionality = "Next Generation Firewall" AND destinationport IN("22","23","3389","53") AND destinationaddress != 10.0.0.0/8 AND destinationaddress != 172.16.0.0/12 AND destinationaddress != 192.168.0.0/16 | STATS SUM(bytesout)

rg_functionality = "Firewall" AND destinationport IN("22","23","3389","53") AND destinationaddress != 10.0.0.0/8 AND destinationaddress != 172.16.0.0/12 AND destinationaddress != 192.168.0.0/16 | STATS SUM(bytesout)
```


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
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "netsh" AND resourcecustomfield1 CONTAINS "advfirewall" AND resourcecustomfield1 CONTAINS "firewall" AND resourcecustomfield1 CONTAINS "Network Discovery" AND resourcecustomfield1 CONTAINS "enable" AND resourcecustomfield1 CONTAINS "Yes" | Rare resourcecustomfield1
```
#### This query detects modification of firewall with netsh command to allow the local file and printers to be discovered on the local network by other computers

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "netsh" AND resourcecustomfield1 CONTAINS "advfirewall" AND resourcecustomfield1 CONTAINS "firewall" AND resourcecustomfield1 CONTAINS "File and Printer Sharing" AND resourcecustomfield1 CONTAINS "enable" AND resourcecustomfield1 CONTAINS "Yes" | Rare resourcecustomfield1
```
#### This query detects modification of LocalAccountTokenFilterPolicy registry key that can be used to disable UAC remote restrictions

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "Microsoft\Windows\CurrentVersion\Policies\System" AND resourcecustomfield1 CONTAINS "LocalAccountTokenFilterPolicy" | Rare resourcecustomfield1
```
#### This query detects Malicious registry modifications by “EnableLinkedConnections” using “reg.exe

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "Microsoft\Windows\CurrentVersion\Policies\System" AND resourcecustomfield1 CONTAINS "EnableLinkedConnections" | Rare resourcecustomfield1
```
#### This query detects Malicious registry modifications by enabling “LongPathsEnabled” within the Filesystem control

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS " add " AND resourcecustomfield1 CONTAINS "SYSTEM\CurrentControlSet\Control\FileSystem" AND resourcecustomfield1 CONTAINS "LongPathsEnabled" | Rare resourcecustomfield1
```
#### This query detects for Malicious Driver Mount Process Creation using the process “mountvol.exe”

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "mountvol.exe" AND resourcecustomfield1 CONTAINS "Volume{" | Rare resourcecustomfield1
```
#### This query detects installation of Active Directory RSAT tools, that allows you to perform basic operations with the AD directory

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "powershell.exe" AND resourcecustomfield1 CONTAINS "Install-WindowsFeature" AND resourcecustomfield1 CONTAINS "-Name" AND resourcecustomfield1 CONTAINS "RSAT-AD-PowerShell"
```
#### This query detects Microsoft Exchange Mailbox Replication service writing Active Server Pages

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction ENDS WITH "Written" OR deviceaction = "File created") AND destinationprocessname ENDS WITH "MSExchangeMailboxReplication.exe" AND filename CONTAINS "\frontend\httpproxy\owa\auth\current\themes" AND filename ENDS WITH ".aspx" | rare filename
```
#### This query Detects parameterless use of processes Wuauclt.exe

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "wuauclt.exe" AND (resourcecustomfield1 ENDS WITH "wuauclt.exe" OR resourcecustomfield1 ENDS WITH "wuauclt.exe"") | Rare limit=10 resourcecustomfield1
```
#### This query Monitors for  Print bombing where the process “cmd” launches “wordpad” or “notepad” doc files and prints using “/p” command. Monitor for a spike in this activity.

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND destinationprocessname ENDS WITH "cmd.exe" AND (resourcecustomfield1 CONTAINS "wordpad.exe" OR resourcecustomfield1 CONTAINS "notepad.exe") AND resourcecustomfield1 CONTAINS "/p" | stats accountname resourceucstomfield1
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
