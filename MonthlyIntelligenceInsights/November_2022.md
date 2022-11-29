# APT 36

#### Next Generation Firewall
```text
(rg_functionality = “Next Generation Firewall” OR rg_functionality = “Web Application Firewall” OR rg_functionality = “Web Server” OR rg_functionality = “Web Proxy”) AND (requesturl CONTAINS “kavach-app” OR requesturl CONTAINS “kavachguide” OR requesturl CONTAINS “getkavach” OR requesturl CONTAINS “kavachsupport” OR requesturl CONTAINS “kavachsupport” OR requesturl CONTAINS “kavachdownload” OR requesturl CONTAINS “kavachauthentication”)
```

# Billbug threat group

#### Microsoft Windows
```text
rg_functionality = ""Microsoft Windows"" AND baseeventid = 4688 AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND (resourcecustomfield1 contains ""advfirewall"" and resourcecustomfield1 contains ""set rule group=remote"" and resourcecustomfield1 contains ""desktop new enable=Yes"")
```

#### Endpoint Management Systems
```text
rg_functionality = ""Endpoint Management Systems"" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND ((resourcecustomfield1 contains ""advfirewall"" and resourcecustomfield1 contains ""set rule group=remote"" and resourcecustomfield1 contains ""desktop new enable=Yes"") OR (resourcecustomfield2 contains ""advfirewall"" and resourcecustomfield2 contains ""set rule group=remote"" and resourcecustomfield2 contains ""desktop new enable=Yes""))
```

#### Antivirus / Malware / EDR
```text
rg_functionality = ""Antivirus / Malware / EDR"" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND ((resourcecustomfield1 contains ""advfirewall"" and resourcecustomfield1 contains ""set rule group=remote"" and resourcecustomfield1 contains ""desktop new enable=Yes"") OR (resourcecustomfield2 contains ""advfirewall"" and resourcecustomfield2 contains ""set rule group=remote"" and resourcecustomfield2 contains ""desktop new enable=Yes""))
```

#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = ""Cloud Antivirus / Malware / EDR"" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”)  AND (sourceprocessname contains netsh or destinationprocessname contains netsh) AND ((resourcecustomfield1 contains ""advfirewall"" and resourcecustomfield1 contains ""set rule group=remote"" and resourcecustomfield1 contains ""desktop new enable=Yes"") OR (resourcecustomfield2 contains ""advfirewall"" and resourcecustomfield2 contains ""set rule group=remote"" and resourcecustomfield2 contains ""desktop new enable=Yes""))"
```

# ARCrypter Ransomware 

#### Next Generation Firewall
```text
(rg_functionality = “Next Generation Firewall” OR rg_functionality = “Web Application Firewall” OR rg_functionality = “Web Server” OR rg_functionality = “Web Proxy”) AND (requesturl CONTAINS “win.exe” OR requesturl CONTAINS “win.zip”)
```

# QakBot Malware

#### Next Generation Firewall
```text
(rg_functionality = “Next Generation Firewall” OR rg_functionality = “Web Application Firewall” OR rg_functionality = “Web Server” OR rg_functionality = “Web Proxy”) AND (requesturl CONTAINS “win.exe” OR requesturl CONTAINS “win.zip”)
```

#### Endpoint Management Systems
```text
rg_functionality= "Endpoint Management Systems" and filepath="C:\Windows\PsExec.exe" and eventid=11 and filename="psexec.exe"
```

```text
rg_functionality =  "Endpoint Management Systems" and (eventid=1 or eventid=4688)  and (processname="regsvr32.exe" or destinationprocessname="regsvr32.exe") and (childprocesscommandline contains "/s \\"  or childprocesscommandline contains "-s \\")
```

```text
rg_functionality =  "Endpoint Management Systems" and (eventid=1 or eventid=4688)  AND (processname="regsvr32.exe" or destinationprocessname="regsvr32.exe") and (commandline contains "/s \\" or commandline contains "-s \\")
```





