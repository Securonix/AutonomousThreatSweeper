# Linux ransomware Cheerscrypt

#### Next Generation Firewall
```text
rg_functionality = “Next Generation Firewall” AND ((requestclientapplication NOT NULL AND requestclientapplication CONTAINS "jndi" AND ipaddress NOT NULL) AND (requestclientapplication CONTAINS "dns" OR requestclientapplication CONTAINS "rmi" OR requestclientapplication CONTAINS "lower" OR requestclientapplication CONTAINS "upper" OR requestclientapplication CONTAINS "ldap" OR requestclientapplication CONTAINS "nis" OR requestclientapplication CONTAINS "iiop" OR requestclientapplication CONTAINS "corba" OR requestclientapplication CONTAINS "nds" OR requestclientapplication CONTAINS "http")) OR ((ipaddress NOT NULL AND requestclientapplication NOT NULL) AND ( requestclientapplication CONTAINS "${upper:" OR requestclientapplication CONTAINS "${lower:"OR requestclientapplication CONTAINS "${::" OR requestclientapplication CONTAINS "%7Bjndi" OR requestclientapplication CONTAINS "$%7Benv:" OR requestclientapplication CONTAINS "${env:" OR requestclientapplication CONTAINS "${base64:" OR requestclientapplication CONTAINS "257Bjndi" OR requestclientapplication CONTAINS "%6a" OR requestclientapplication CONTAINS "%4a" OR requestclientapplication CONTAINS "%6e" OR requestclientapplication CONTAINS "%1e" OR requestclientapplication CONTAINS "%14" OR requestclientapplication CONTAINS "%64" OR requestclientapplication CONTAINS "%19" OR requestclientapplication CONTAINS "%69" OR requestclientapplication CONTAINS "}${" OR requestclientapplication CONTAINS "${ctx:" OR requestclientapplication CONTAINS "${sd:" OR requestclientapplication CONTAINS "${map:" OR requestclientapplication CONTAINS ":-j}$")
```

# New Maggie Malware

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "ProcessCreate" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "SyntheticProcessRollUp2" OR deviceaction = "WmiCreateProcess" OR deviceaction = "Trace Executed Process" OR deviceaction = "Process" OR deviceaction = "Childproc" OR deviceaction = "Procstart" OR deviceaction = "Process Activity: Launched") AND (destinationprocessname = "ExtendedProcedure.DLL" or sourceprocessname = "ExtendedProcedure.DLL") AND (destinationprocessname = "sqlmaggieAntiVirus_64.dll" or sourceprocessname = "sqlmaggieAntiVirus_64.dll")
```

# LockBit 3.0 Ransomware

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "Procstart" OR deviceaction = "Process" OR deviceaction = "Trace Executed Process") AND (sourceprocessname = "eqnedt32.exe" OR sourceprocessname = "excel.exe" OR sourceprocessname = "fltldr.exe" OR sourceprocessname = "msaccess.exe" OR sourceprocessname = "mspub.exe" OR sourceprocessname = "powerpnt.exe" OR sourceprocessname = "winword.exe" OR sourceprocessname = "outlook.exe") AND (destinationprocessname = "Microsoft.Workflow.Compiler.exe" OR destinationprocessname = "atbroker.exe" OR destinationprocessname = "bitsadmin.exe" OR destinationprocessname = "cdb.exe" OR destinationprocessname = "certutil.exe" OR destinationprocessname = "cmd.exe" OR destinationprocessname = "cmstp.exe" OR destinationprocessname = "control.exe" OR destinationprocessname = "cscript.exe" OR destinationprocessname = "csi.exe" OR destinationprocessname = "dnx.exe" OR destinationprocessname = "dsget.exe" OR destinationprocessname = "dsquery.exe" OR destinationprocessname = "forfiles.exe" OR destinationprocessname = "fsi.exe" OR destinationprocessname = "ftp.exe" OR destinationprocessname = "ieexec.exe" OR destinationprocessname = "iexpress.exe" OR destinationprocessname = "installutil.exe" OR destinationprocessname = "mshta.exe" OR destinationprocessname = "msxsl.exe" OR destinationprocessname = "net.exe" OR destinationprocessname = "net1.exe" OR destinationprocessname = "netsh.exe" OR destinationprocessname = "nltest.exe" OR destinationprocessname = "odbcconf.exe" OR destinationprocessname = "powershell.exe" OR destinationprocessname = "pwsh.exe" OR destinationprocessname = "qprocess.exe" OR destinationprocessname = "qwinsta.exe" OR destinationprocessname = "rcsi.exe" OR destinationprocessname = "reg.exe" OR destinationprocessname = "regasm.exe" OR destinationprocessname = "regsvcs.exe" OR destinationprocessname = "regsvr32.exe" OR destinationprocessname = "sc.exe" OR destinationprocessname = "schtasks.exe" OR destinationprocessname = "wmic.exe" OR destinationprocessname = "wscript.exe" OR destinationprocessname = "xwizard.exe" OR destinationprocessname = "rundll32.exe" OR destinationprocessname = "hh.exe" OR destinationprocessname = "msdt.exe") AND (resourcecustomfield1 NOT CONTAINS "MonitorPrintJobStatus" OR resourcecustomfield1 NOT CONTAINS "NetworkDiagnosticsSharing")
```

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = ""Process Create"" OR deviceaction = ""ProcessCreate"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND (destinationprocessname = ""DECRYPTION_ID.txt"" or sourceprocessname = ""DECRYPTION_ID.txt"") AND (destinationprocessname = ""LB3.exe"" or sourceprocessname = ""LB3.exe"") AND (destinationprocessname = ""LB3Decryptor.exe "" or sourceprocessname = ""LB3Decryptor.exe"") AND (destinationprocessname = ""LB3_pass.exe"" or sourceprocessname = ""LB3_pass.exe"") AND (destinationprocessname = ""LB3_RelectiveDLL_DLLMain.dll"" or sourceprocessname = ""LB3_RelectiveDLL_DLLMain.dll"") AND (destinationprocessname = ""LB3_Rundll32.dll"" or sourceprocessname = ""LB3_Rundll32.dll"") AND (destinationprocessname = ""LB3_Rundll32_pass.dll"" or sourceprocessname = ""LB3_Rundll32_pass.dll"") AND (destinationprocessname = ""Password_dll.txt"" or sourceprocessname = ""Password_dll.txt"") AND (destinationprocessname = ""Password_exe.tx"" or sourceprocessname = ""Password_exe.tx"")
```

# Lazarus Group

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = ""Process Create"" OR deviceaction = ""ProcessCreate"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND (destinationprocessname = ""scskapplink.dll"" or sourceprocessname = ""scskapplink.dll"") AND (destinationprocessname = ""inisafecrosswebexsvc.exe"" or sourceprocessname = ""inisafecrosswebexsvc.exe"")"
```

# Alchimist and Insekt Malware

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

# Zero Day Vulnerabilities in Microsoft Exchange Server

#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND (sourceprocessname = powershell.exe OR destinationprocessname = powershell.exe) AND (resourcecustomfield1 CONTAINS "http://" OR resourcecustomfield1 CONTAINS "https://") | RARE resourcecustomfield1
```

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND resourcecustomfield1 CONTAINS "powershell -w h -NoProfile -ExecutionPolicy Bypass - Command start-sleep -s 20;iwr" | RARE resourcecustomfield1
```

#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND (sourceprocessname = powershell.exe OR destinationprocessname = powershell.exe) AND (resourcecustomfield1 CONTAINS "http://" OR resourcecustomfield1 CONTAINS "https://") | RARE resourcecustomfield1
```

```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4688 AND resourcecustomfield1 CONTAINS "powershell -w h -NoProfile -ExecutionPolicy Bypass - Command start-sleep -s 20;iwr" | RARE resourcecustomfield1
```
