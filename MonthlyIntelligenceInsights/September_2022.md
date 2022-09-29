# Lazarus Group

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND customstring54 ENDS WITH "node.exe" AND resourcecustomfield1 CONTAINS "net -e" AND resourcecustomfield1 CONTAINS ".exec(" AND (resourcecustomfield1 CONTAINS cmd.exe OR resourcecustomfield1 CONTAINS powershell.exe) AND resourcecustomfield1 CONTAINS "net.socket()" AND resourcecustomfield1 CONTAINS ".connect("

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open")  AND ( ( destinationprocessname = "pwsh.exe" OR destinationprocessname = "sqlps.exe" OR estinationprocessname = "sqltoolsps.exe" OR destinationprocessname = "powershell.exe" OR destinationprocessname = "powershell_ise.exe" OR destinationprocessname = "pwsh.dll" ) OR ( customstring49 = "PowerShell.EXE" OR customstring49 = "powershell_ise.EXE" ) ) AND ( resourcecustomfield1 CONTAINS ".DownloadString" )

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND ( ( resourcecustomfield1 CONTAINS "ipconfig" AND resourcecustomfield1 CONTAINS "/all" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "config" AND resourcecustomfield1 CONTAINS "workstation" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "view" AND resourcecustomfield1 CONTAINS "/all" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "view" AND resourcecustomfield1 CONTAINS "/all" AND resourcecustomfield1 CONTAINS "/doma" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/domain_trusts" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/domain_trusts" AND resourcecustomfield1 CONTAINS "/all_trusts" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "group" AND resourcecustomfield1 CONTAINS "Domain Computers" AND resourcecustomfield1 CONTAINS "/dom" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "group" AND resourcecustomfield1 CONTAINS "Enterprise Admins" AND resourcecustomfield1 CONTAINS "/dom" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/dclist:" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "domainlist" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "dclist" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "trustdmp" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "adinfo" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "dcmodes" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-subnets" AND resourcecustomfield1 CONTAINS "-f" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-gcb" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "trustdmp" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-f" AND resourcecustomfield1 CONTAINS "objectcategory=computer" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-f" AND resourcecustomfield1 CONTAINS "objectcategory=person" ) )

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND resourcecustomfield1 CONTAINS "Set-MpPreference" AND resourcecustomfield1 CONTAINS "DisableRealtimeMonitoring"

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND (customstring54 ENDS WITH "powershell.exe" OR customstring54 ENDS WITH “powershell_ise.exe”) AND resourcecustomfield1 CONTAINS "-exec" AND resourcecustomfield1 CONTAINS "DownloadFile"

rg_functionality = "Endpoint Management Systems" AND deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND (customstring54 ENDS WITH “rar.exe” OR customstring54 ENDS WITH “7za.exe” OR customstring54 ENDS WITH “7z.exe” OR customstring54 ENDS WITH “unrar.exe”) AND (resourcecustomfield1 CONTAINS " a " OR resourcecustomfield1 CONTAINS “ e ”)

rg_functionality = "Endpoint Management Systems" AND deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND (customstring54 ENDS WITH “rar.exe” OR customstring54 ENDS WITH “7za.exe” OR customstring54 ENDS WITH “7z.exe” OR customstring54 ENDS WITH “unrar.exe”) AND ((resourcecustomfield1 CONTAINS "a" ) AND ( resourcecustomfield1 CONTAINS "-hp" OR resourcecustomfield1 CONTAINS "-p" OR resourcecustomfield1 CONTAINS "-dw" OR resourcecustomfield1 CONTAINS "-tb" OR resourcecustomfield1 CONTAINS "-ta" OR resourcecustomfield1 CONTAINS "/hp" OR resourcecustomfield1 CONTAINS "/p" OR resourcecustomfield1 CONTAINS "/dw" OR resourcecustomfield1 CONTAINS "/tb" OR resourcecustomfield1 CONTAINS "/t" ) AND ( resourcecustomfield1 CONTAINS "-p" OR resourcecustomfield1 CONTAINS "-sdel" ))

rg_functionality = "Endpoint Management Systems" AND deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND resourcecustomfield1 IN ("systeminfo","ipconfig ","netstat" ,"tasklist ","net ", "query","dir ",)

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND customstring54 ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS "add" AND resourcecustomfield1 CONTAINS "\SecurityProviders\WDigest" AND resourcecustomfield1 CONTAINS "UseLogonCredential" AND resourcecustomfield1 CONTAINS "/t" AND resourcecustomfield1 CONTAINS "REG_DWORD" AND resourcecustomfield1 CONTAINS "/d"

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND customstring54 ENDS WITH “reg.exe” AND resourcecustomfield1 CONTAINS “add” AND resourcecustomfield1 CONTAINS “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon” AND resourcecustomfield1 CONTAINS “AllowMultipleTSSessions”

rg_functionality = "Endpoint Management Systems" AND deviceaction IN ("ProcessRollup2", "Procstart", "Childproc", "Process", "Process Create", "Trace Executed Process", "Process Create (rule: ProcessCreate)", "Process Activity: Launched", "Process Activity: Open", "Process History: Launched", "Process History: Open") AND customstring54 ENDS WITH “reg.exe” AND resourcecustomfield1 CONTAINS “add”  AND resourcecustomfield1 CONTAINS “Microsoft\Windows\CurrentVersion\Policies\System” AND resourcecustomfield1 CONTAINS “LocalAccountTokenFilterPolicy”

rg_functionality = "Endpoint Management Systems" AND deviceaction IN ("ProcessRollup2", "Procstart", "Childproc", "Process", "Process Create", "Trace Executed Process", "Process Create (rule: ProcessCreate)", "Process Activity: Launched", "Process Activity: Open", "Process History: Launched", "Process History: Open") AND customstring54 ENDS WITH “reg.exe” AND resourcecustomfield1 CONTAINS “add”  AND resourcecustomfield1 CONTAINS “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa” AND resourcecustomfield1 CONTAINS “LmCompatibilityLevel”

rg_functionality = "Endpoint Management Systems" AND deviceaction IN ("ProcessRollup2", "Procstart", "Childproc", "Process", "Process Create", "Trace Executed Process", "Process Create (rule: ProcessCreate)", "Process Activity: Launched", "Process Activity: Open", "Process History: Launched", "Process History: Open") and customstring29 = “osc.exe” and resourcecustomfield1 CONTAINS “-i” and resourcecustomfield1 CONTAINS “-p”

rg_functionality = "Endpoint Management Systems" AND deviceaction IN ("ProcessRollup2", "Procstart", "Childproc", "Process", "Process Create", "Trace Executed Process", "Process Create (rule: ProcessCreate)", "Process Activity: Launched", "Process Activity: Open", "Process History: Launched", "Process History: Open") AND customstring29 = “plink.exe” and resourcecustomfield1 CONTAINS “-R” and resourcecustomfield1 CONTAINS “-P” and resourcecustomfield1 CONTAINS “-l” and resourcecustomfield1 CONTAINS “-pw”

rg_functionality = “Endpoint Management Systems” AND deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND resourcecustomfield1 CONTAINS “sc create” AND resourcecustomfield1 CONTAINS “start= auto” AND resourcecustomfield1 CONTAINS “error= ignore”

rg_functionality = "Endpoint Management Systems" AND deviceaction IN ("ProcessRollup2", "Procstart", "Childproc", "Process", "Process Create", "Trace Executed Process", "Process Create (rule: ProcessCreate)", "Process Activity: Launched", "Process Activity: Open", "Process History: Launched", "Process History: Open") AND customstring54 ENDS WITH "reg.exe" and resourcecustomfield1 CONTAINS "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" and resourcecustomfield1 CONTAINS "/v" and resourcecustomfield1 CONTAINS "/t" and resourcecustomfield1 CONTAINS "/d" and resourcecustomfield1 CONTAINS "/f"

rg_functionality = "Endpoint Management Systems" AND deviceaction IN ("ProcessRollup2", "Procstart", "Childproc", "Process", "Process Create", "Trace Executed Process", "Process Create (rule: ProcessCreate)", "Process Activity: Launched", "Process Activity: Open", "Process History: Launched", "Process History: Open") AND customstring54 ENDS WITH "schtasks.exe" and resourcecustomfield1 CONTAINS "/create" and resourcecustomfield1 CONTAINS "/sc onlogon"

rg_functionality = "Endpoint Management Systems" AND deviceaction IN ("ProcessRollup2", "Procstart", "Childproc", "Process", "Process Create", "Trace Executed Process", "Process Create (rule: ProcessCreate)", "Process Activity: Launched", "Process Activity: Open", "Process History: Launched", "Process History: Open") AND customstring54 ENDS WITH "schtasks.exe" and resourcecustomfield1 CONTAINS "/create" and resourcecustomfield1 CONTAINS "/sc onstart"
```

#### Microsoft Windows
```text
rg_functionality = “Microsoft Windows” AND (baseeventid = 4720 OR baseeventid = 624) AND (sourcentdomain CONTAINS destinationntdomain OR destinationntdomain CONTAINS sourcentdomain) AND (accountname != - AND accountname NOT CONTAINS $) AND (destinationusername NOT NULL AND destinationusername != - AND destinationusername NOT CONTAINS svc AND destinationusername NOT CONTAINS $)

rg_functionality = “Microsoft Windows” AND  (baseeventid = 4728 OR baseeventid = 4732 OR baseeventid = 4756)
```

# MagicRAT Trojan

### Scheduled Task creation 

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" and resourcecustomfield1 CONTAINS "schtasks" AND resourcecustomfield1 CONTAINS "/Create" AND accountname NOT CONTAINS "SYSTEM" AND (resourcecustomfield1 CONTAINS "/st" OR resourcecustomfield1 CONTAINS "/sc" )
```

### Commnad Execution

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" and deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND ( ( resourcecustomfield1 CONTAINS "ipconfig" AND resourcecustomfield1 CONTAINS "/all" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "config" AND resourcecustomfield1 CONTAINS "workstation" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "view" AND resourcecustomfield1 CONTAINS "/all" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "view" AND resourcecustomfield1 CONTAINS "/all" AND resourcecustomfield1 CONTAINS "/doma" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/domain_trusts" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/domain_trusts" AND resourcecustomfield1 CONTAINS "/all_trusts" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "group" AND resourcecustomfield1 CONTAINS "Domain Computers" AND resourcecustomfield1 CONTAINS "/dom" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "group" AND resourcecustomfield1 CONTAINS "Enterprise Admins" AND resourcecustomfield1 CONTAINS "/dom" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/dclist:" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "domainlist" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "dclist" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "trustdmp" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "adinfo" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "dcmodes" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-subnets" AND resourcecustomfield1 CONTAINS "-f" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-gcb" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "trustdmp" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-f" AND resourcecustomfield1 CONTAINS "objectcategory=computer" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-f" AND resourcecustomfield1 CONTAINS "objectcategory=person" ) )
```

# APT28

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND resourcecustomfield1 CONTAINS "lmapi2.dll" AND resourcecustomfield1 CONTAINS "rundll32.exe" AND resourcecustomfield1 CONTAINS "InProcServer32" and AND resourcecustomfield1 CONTAINS "DownloadData"

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND customstring54 ENDS WITH "reg.exe" AND resourcecustomfield1 CONTAINS "add" AND resourcecustomfield1 CONTAINS "HKCU\Software\Classes\CLSID\" and resourcecustomfield1 CONTAINS "InProcServer32" AND resourcecustomfield1 CONTAINS "/d" AND resourcecustomfield1 CONTAINS "Imapi2.dll" AND resourcecustomfield1 CONTAINS "rundll32.exe"

rg_functionality = "Endpoint Management Systems" AND  deviceaction in ("ProcessRollup2", "Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND customstring54 ENDS WITH "SyncAppvPublishingServer.exe" AND resourcecustomfield1 CONTAINS "lmapi2.dll" AND resourcecustomfield1 CONTAINS "rundll32.exe" AND resourcecustomfield1 CONTAINS "InProcServer32" and AND resourcecustomfield1 CONTAINS "DownloadData"
```

#### Microsoft Powershell
```text
rg_functionality = "Microsoft Powershell" and baseeventid = 4104 AND ((message CONTAINS "lmapi2.dll" AND message CONTAINS "rundll32.exe" AND message CONTAINS "InProcServer32" and AND message CONTAINS "DownloadData") OR (devicecustomstring1 CONTAINS "lmapi2.dll" AND devicecustomstring1 CONTAINS "rundll32.exe" AND devicecustomstring1 CONTAINS "InProcServer32" and AND devicecustomstring1 CONTAINS "DownloadData"))
```


# STEEP#MAVERICK

### Below queries looks for rare powershell commands execution

#### Endpoint Management Systems
```text
rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND (sourceprocessname = powershell.exe OR destinationprocessname = powershell.exe) AND (resourcecustomfield1 CONTAINS ""http://"" OR resourcecustomfield1 CONTAINS ""https://"") | RARE resourcecustomfield1

rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND resourcecustomfield1 CONTAINS ""powershell -w h -NoProfile -ExecutionPolicy Bypass - Command start-sleep -s 20;iwr"" | RARE resourcecustomfield1
```

### Below queries looks for value containing a malicious PowerShell script, embedding itself into the registry

#### Endpoint Management Systems
```text
rg_functionality = “Endpoint Management Systems” AND transactionstring5 = “SetValue” AND devicecustomstring2 CONTAINS “\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2”
```

#### Microsoft Windows
```text
rg_functionality = ""Microsoft Windows"" AND baseeventid = 4688 AND (sourceprocessname = powershell.exe OR destinationprocessname = powershell.exe) AND (resourcecustomfield1 CONTAINS ""http://"" OR resourcecustomfield1 CONTAINS ""https://"") | RARE resourcecustomfield1

rg_functionality = ""Microsoft Windows"" AND baseeventid = 4688 AND resourcecustomfield1 CONTAINS ""powershell -w h -NoProfile -ExecutionPolicy Bypass -Command start-sleep -s 20;iwr"" | RARE resourcecustomfield1
```
