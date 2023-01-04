# New CryWiper Trojan

#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains browserupdate.exe or destinationprocessname contains browserupdate.exe) AND (resourcecustomfield1 contains "browserupdate.exe" or resourcecustomfield2 contains "browserupdate.exe")
```

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" and resourcecustomfield1 CONTAINS "schtasks" AND resourcecustomfield1 CONTAINS "/Create" AND accountname NT CONTAINS "SYSTEM" AND (resourcecustomfield1 CONTAINS "/st" OR resourcecustomfield1 CONTAINS "/sc" ) 
```

```text
rg_functionality = "Endpoint Management Systems" and  deviceaction in ("ProcessRollup2","Procstart","Childproc","Process","Process Create","Trace Executed Process","Process Create (rule: ProcessCreate)","Process Activity: Launched","Process Activity: Open","Process History: Launched","Process History: Open") AND ( ( resourcecustomfield1 CONTAINS "ipconfig" AND resourcecustomfield1 CONTAINS "/all" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "config" AND resourcecustomfield1 CONTAINS "workstation" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "view" AND resourcecustomfield1 CONTAINS "/all" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "view" AND resourcecustomfield1 CONTAINS "/all" AND resourcecustomfield1 CONTAINS "/doma" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/domain_trusts" ) OR ( resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/domain_trusts" AND resourcecustomfield1 CONTAINS "/all_trusts" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "group" AND resourcecustomfield1 CONTAINS "Domain Computers" AND resourcecustomfield1 CONTAINS "/dom" ) OR ( resourcecustomfield1 CONTAINS "net" AND resourcecustomfield1 CONTAINS "group" AND resourcecustomfield1 CONTAINS "Enterprise Admins" AND resourcecustomfield1 CONTAINS "/dom" ) OR resourcecustomfield1 CONTAINS "nltest" AND resourcecustomfield1 CONTAINS "/dclist:" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "domainlist" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "dclist" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "trustdmp" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "adinfo" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "dcmodes" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-subnets" AND resourcecustomfield1 CONTAINS "-f" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-gcb" AND resourcecustomfield1 CONTAINS "-sc" AND resourcecustomfield1 CONTAINS "trustdmp" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-f" AND resourcecustomfield1 CONTAINS "objectcategory=computer" ) OR ( resourcecustomfield1 CONTAINS "adfind" AND resourcecustomfield1 CONTAINS "-f" AND resourcecustomfield1 CONTAINS "objectcategory=person" ) )
```

```text
rg_functionality = "Endpoint Management Systems" AND (resourcecustomfield1 CONTAINS "vssadmin delete shadows /all /quiet" OR resourcecustomfield1 CONTAINS "bcdedit /set {default} recoveryenabled No" OR resourcecustomfield1 CONTAINS "wmic SHADOWCOPY /nointeractive" OR (resourcecustomfield1 CONTAINS "fsutil file setZeroData offset=0 length=524288" AND resourcecustomfield1 CONTAINS "C:\Windows\LockBit_"))
```

# New Agrius threat group 

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "ProcessCreate" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND (sourceprocessname = "mimikatz.exe" OR destinationprocessname = "mimikatz.exe" OR sourceprocessname = "pypykatz.exe" OR destinationprocessname = "pypykatz.exe"
```

#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains fantasy45.exe or destinationprocessname contains fantasy45.exe) AND (resourcecustomfield1 contains "fantasy45.exe" or resourcecustomfield2 contains "fantasy45.exe") AND (sourceprocessname contains fantasy35.exe or destinationprocessname contains fantasy35.exe) AND (resourcecustomfield1 contains "fantasy35.exe" or resourcecustomfield2 contains "fantasy35.exe")
```

# New Zerobot 1.1

#### Unix / Linux / AIX
```text
rg_functionality = "Unix / Linux / AIX" AND resourcecustomfield5 CONTAINS "$HOME/.config/ssh.service/sshf" AND (resourcecustomfield5 CONTAINS "sshf")
```


# STEPPY#KAVACH

#### Endpoint Management Systems
```text
rg_functionality = “Endpoint Management Systems” AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND sourceprocessname = “mshta.exe” AND (destinationprocessname = “powershell.exe” OR destinationprocessname = “cscript.exe” OR destinationprocessname E= “wscript.exe” OR destinationprocessname = “msiexec.exe” OR destinationprocessname = “rundll32.exe” OR destinationprocessname = “msbuild.exe”)
```

```text
rg_functionality = “Endpoint Management Systems” AND (deviceaction ENDS WITH “Written” OR deviceaction = “File created”) AND (customstring49 ENDS WITH “\ProgramData\8292.png” OR filepath ENDS WITH “\ProgramData\mm1.exe” OR customstring49 ENDS WITH “\ProgramData\kohl.js” OR customstring49 ENDS WITH “\ProgramData\kohlw.js” OR customstring49 ENDS WITH “\ProgramData\kohld.js” OR customstring49 ENDS WITH “\ProgramData\update.js” OR customstring49 ENDS WITH “\ProgramData\parhai.js” OR customstring49 ENDS WITH “\ProgramData\r.js” OR customstring49 ENDS WITH “\ProgramData\kohlw.js”)
```

```text
rg_functionality = “Endpoint Management Systems” AND deviceaction = “Network connection detected” AND destinationprocessname = “mshta.exe” AND (destinationaddress != “10.0.0.0/8” OR destinationaddress != “172.16.0.0/12” OR destinationaddress != “192.168.0.0/16” OR destinationaddress != “127.0.0.1” OR destinationaddress != “127.0.0.0/8” OR destinationaddress != “169.254.0.0/16”)
```
