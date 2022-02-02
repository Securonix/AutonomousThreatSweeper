## SysJoker Backdoor

__Microsoft Windows__:

### The following query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”

```text
index=activity and rg_functionality = "Microsoft Windows'' and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath

```
__Antivirus / Malware / EDR__:
```text
The following query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”
```

```text
index=activity and rg_functionality = "Antivirus / Malware / EDR" and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2
```

```text
The following query detects the registry modification in the below registry path post execution.
```

```text
index=activity and rg_functionality = "Antivirus / Malware / EDR" and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2

```

__Cloud Antivirus / Malware / EDR__:
```text
The following query looks for rare files downloaded and executed in mentioned directories where the backdoor has been observed to operate
```

```text
index=activity and rg_functionality = "Microsoft Windows" and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath
```

```text
The following query detects the registry modifications for persistence.
```

```text
index=activity and rg_functionality = "Cloud Antivirus / Malware / EDR" and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2
```
__Endpoint Management Systems__:
```text
The following query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”
```

```text
index=activity and rg_functionality = "Microsoft Windows" and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath
```

```text
The following query detects the registry modification to maintain persistence.
```

```text
index=activity and rg_functionality = “Endpoint management Systems” and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2
```

## WhisperGate Malware

__Endpoint Management Systems__:
```text
These queries are split into two parts, one query looks for the stage1.exe executable specifically and the other query looks for rare files executed from the referenced paths.
```
```text
rg_functionality = "Endpoint Management Systems" AND (sourceprocessname contains "stage1.exe" or destinationprocessname contains "stage1.exe" OR filename CONTAINS "stage1.exe" OR filepath CONTAINS "stage1.exe" OR oldfilename CONTAINS "stage1.exe" OR oldfilepath CONTAINS "stage1.exe")

rg_functionality = "Endpoint Management Systems" AND (filepath CONTAINS "C:\PerfLogs" OR filepath CONTAINS "C:\ProgramData" OR filepath CONTAINS "C:\" OR filepath CONTAINS "C:\temp" OR oldfilepath CONTAINS "C:\PerfLogs" OR oldfilepath CONTAINS "C:\ProgramData" OR oldfilepath CONTAINS "C:\" OR oldfilepath CONTAINS "C:\temp") | RARE filename
```
```text
The following query detects rare downloads from the discord CDN. NOTE: The following query has the potential to generate false positives and should be used in conjunction with unusual downloads from a discord cdn
```
```text
index=activity AND rg_functionality = "Endpoint Management Systems" AND deviceaction = "Dns query" AND destinationhostname ENDS WITH "cdn.discordapp.com" AND destinationprocessname NOT ENDS WITH "discord.exe" AND destinationprocessname NOT ENDS WITH "chrome.exe" AND destinationprocessname NOT ENDS WITH "firefox.exe" AND destinationprocessname NOT ENDS WITH "safari.exe" AND destinationprocessname NOT ENDS WITH "opera.exe" AND destinationprocessname NOT ENDS WITH "iexplore.exe" AND destinationprocessname NOT ENDS WITH "microsoftedge.exe" OR destinationprocessname NOT ENDS WITH "microsoftedgecp.exe" AND destinationprocessname NOT ENDS WITH "browser_broker.exe" AND destinationprocessname NOT ENDS WITH "msedge.exe" AND destinationprocessname NOT ENDS WITH "brave.exe" | RARE filename
```
```text
Summary: The following query looks for rare files written in the temp directory via VB script leveraging i.e. leveraging the Wscript.exe process.
```
```text
rg_functionality = "Endpoint Management Systems" AND sourceprocessname = WScript.exe AND filepath CONTAINS "temp" | RARE filename
```
```text
The following query looks for rare path exclusions using powershell.exe, this may be used for defence evasion. 
```
```text
rg_functionality = ""Endpoint Management Systems"" AND sourceprocessname = powershell.exe AND (resourcecustomfield1 CONTAINS ""-ExclusionPath"" OR resourcecustomfield3 CONTAINS ""-ExclusionPath"")"
```
```text
The following query looks for rare vbs file creations.
```
```text
index=activity AND rg_functionality = ""Endpoint Management Systems"" AND (deviceaction ENDS WITH ""Written"" OR deviceaction = ""File created"") AND resourcecustomfield5 CONTAINS ""\AppData\Local\Temp"" AND resourcecustomfield5 ENDS WITH "".vbs"" | RARE resourcecustomfield5"
```
```text
The following query looks for configuration preferences for Windows Defender with rare path exclusion.
```
```text
index=activity AND g_functionality = ""Endpoint Management Systems"" AND (deviceaction = ""Process Create"" OR deviceaction = ""Process Create (rule: ProcessCreate)"" OR deviceaction = ""ProcessRollup2"" OR deviceaction = ""SyntheticProcessRollUp2"" OR deviceaction = ""WmiCreateProcess"" OR deviceaction = ""Trace Executed Process"" OR deviceaction = ""Process"" OR deviceaction = ""Childproc"" OR deviceaction = ""Procstart"" OR deviceaction = ""Process Activity: Launched"") AND resourcecustomfield1 CONTAINS ""Set-MpPreference"" AND resourcecustomfield1 CONTAINS ""ExclusionPath"""
```
```text
There are two parts to The following query where one looks for advancedrun.exe process to stop Windows Defender and the other query looks for rare processes that are leveraged to stop Windows Defender in general. 
```
```text
rg_functionality = ""Endpoint Management Systems"" AND sourceprocessname = AdvancedRun.exe AND (resourcecustomfield1 CONTAINS ""stop WinDefend"" OR resourcecustomfield3 CONTAINS ""stop WinDefend"")

rg_functionality = ""Endpoint Management Systems"" AND (resourcecustomfield1 CONTAINS ""stop WinDefend"" OR resourcecustomfield3 CONTAINS ""stop WinDefend"") | RARE sourceprocessname"
```
```text
The following query looks for rare filenames and processes from the list of known file types indicative of the file corruptor included in the last stage. Note: The following query has the potential to generate noise and should be used in conjunction with other activities related to this attack."
```
```text
rg_functionality = ""Endpoint Management Systems"" AND (filename CONTAINS "".3DM"" OR filename CONTAINS "".3DS"" OR filename CONTAINS "".602"" OR filename CONTAINS "".7Z"" OR filename CONTAINS "".ACCDB"" OR filename CONTAINS "".AI"" OR filename CONTAINS "".ARC"" OR filename CONTAINS "".ASC"" OR filename CONTAINS "".ASM"" OR filename CONTAINS "".ASP"" OR filename CONTAINS "".ASPX"" OR filename CONTAINS "".BACKUP"" OR filename CONTAINS "".BAK"" OR filename CONTAINS "".BAT"" OR filename CONTAINS "".BMP"" OR filename CONTAINS "".BRD"" OR filename CONTAINS "".BZ"" OR filename CONTAINS "".BZ2"" OR filename CONTAINS "".C"" OR filename CONTAINS "".CGM"" OR filename CONTAINS "".CLASS"" OR filename CONTAINS "".CMD"" OR filename CONTAINS "".CONFIG"" OR filename CONTAINS "".CPP"" OR filename CONTAINS "".CRT"" OR filename CONTAINS "".CS"" OR filename CONTAINS "".CSR"" OR filename CONTAINS "".CSV"" OR filename CONTAINS "".DB"" OR filename CONTAINS "".DBF"" OR filename CONTAINS "".DCH"" OR filename CONTAINS "".DER"" OR filename CONTAINS "".DIF filename CONTAINS "".DIP"" OR filename CONTAINS "".DJVU.SH"" OR filename CONTAINS "".DOC"" OR filename CONTAINS "".DOCB"" OR filename CONTAINS "".DOCM"" OR filename CONTAINS "".DOCX"" OR filename CONTAINS "".DOT"" OR filename CONTAINS "".DOTM"" OR filename CONTAINS "".DOTX"" OR filename CONTAINS "".DWG"" OR filename CONTAINS "".EDB"" OR filename CONTAINS "".EML"" OR filename CONTAINS "".FRM"" OR filename CONTAINS "".GIF"" OR filename CONTAINS "".GO"" OR filename CONTAINS "".GZ"" OR filename CONTAINS "".H"" OR filename CONTAINS "".HDD"" OR filename CONTAINS "".HTM"" OR filename CONTAINS "".HTML"" OR filename CONTAINS "".HWP"" OR filename CONTAINS "".IBD"" OR filename CONTAINS "".INC"" OR filename CONTAINS "".INI"" OR filename CONTAINS "".ISO"" OR filename CONTAINS "".JAR"" OR filename CONTAINS "".JAVA"" OR filename CONTAINS "".JPEG"" OR filename CONTAINS "".JPG"" OR filename CONTAINS "".JS"" OR filename CONTAINS "".JSP"" OR filename CONTAINS "".KDBX"" OR filename CONTAINS "".KEY"" OR filename CONTAINS "".LAY"" OR filename CONTAINS "".LAY6"" OR filename CONTAINS "".LDF"" OR filename CONTAINS "".LOG"" OR filename CONTAINS "".MAX"" OR filename CONTAINS "".MDB"" OR filename CONTAINS "".MDF"" OR filename CONTAINS "".MML"" OR filename CONTAINS "".MSG"" OR filename CONTAINS "".MYD"" OR filename CONTAINS "".MYI"" OR filename CONTAINS "".NEF"" OR filename CONTAINS "".NVRAM"" OR filename CONTAINS "".ODB"" OR filename CONTAINS "".ODG"" OR filename CONTAINS "".ODP"" OR filename CONTAINS "".ODS"" OR filename CONTAINS "".ODT"" OR filename CONTAINS "".OGG"" OR filename CONTAINS "".ONETOC2"" OR filename CONTAINS "".OST"" OR filename CONTAINS "".OTG"" OR filename CONTAINS "".OTP"" OR filename CONTAINS "".OTS"" OR filename CONTAINS "".OTT"" OR filename CONTAINS "".P12"" OR filename CONTAINS "".PAQ"" OR filename CONTAINS "".PAS"" OR filename CONTAINS "".PDF"" OR filename CONTAINS "".PEM"" OR filename CONTAINS "".PFX"" OR filename CONTAINS "".PHP"" OR filename CONTAINS "".PHP3"" OR filename CONTAINS "".PHP4"" OR filename CONTAINS "".PHP5"" OR filename CONTAINS "".PHP6"" OR filename CONTAINS "".PHP7"" OR filename CONTAINS "".PHPS"" OR filename CONTAINS "".PHTML"" OR filename CONTAINS "".PL"" OR filename CONTAINS "".PNG"" OR filename CONTAINS "".POT"" OR filename CONTAINS "".POTM"" OR filename CONTAINS "".POTX"" OR filename CONTAINS "".PPAM"" OR filename CONTAINS "".PPK"" OR filename CONTAINS "".PPS"" OR filename CONTAINS "".PPSM"" OR filename CONTAINS "".PPSX"" OR filename CONTAIBS "".PPT"" OR filename CONTAINS "".PPTM"" OR filename CONTAINS "".PPTX"" OR filename CONTAINS "".PS1"" OR filename CONTAINS "".PSD"" OR filename CONTAINS "".PST"" OR filename CONTAINS "".PY"" OR filename CONTAINS "".RAR"" OR filename CONTAINS "".RAW"" OR filename CONTAINS "".RB"" OR filename CONTAINS "".RTF"" OR filename CONTAINS "".SAV"" OR filename CONTAINS "".SCH"" OR filename CONTAINS "".SHTML"" OR filename CONTAINS "".SLDM"" OR filename CONTAINS "".SLDX"" OR filename CONTAINS "".SLK"" OR filename CONTAINS "".SLN"" OR filename CONTAINS "".SNT"" OR filename CONTAINS "".SQ3"" OR filename CONTAINS "".SQL"" OR filename CONTAINS "".SQLITE3"" OR filename CONTAINS "".SQLITEDB"" OR filename CONTAINS "".STC"" OR filename CONTAINS "".STD"" OR filename CONTAINS "".STI"" OR filename CONTAINS "".STW"" OR filename CONTAINS "".SUO"" OR filename CONTAINS "".SVG"" OR filename CONTAINS "".SXC"" OR filename CONTAINS "".SXD"" OR filename CONTAINS "".SXI"" OR filename CONTAINS "".SXM"" OR filename CONTAINS "".SXW"" OR filename CONTAINS "".TAR"" OR filename CONTAINS "".TBK"" OR filename CONTAINS "".TGZ"" OR filename CONTAINS "".TIF"" OR filename CONTAINS "".TIFF"" OR filename CONTAINS "".TXT"" OR filename CONTAINS "".UOP"" OR filename CONTAINS "".UOT"" OR filename CONTAINS "".VB"" OR filename CONTAINS "".VBS"" OR filename CONTAINS "".VCD"" OR filename CONTAINS "".VDI"" OR filename CONTAINS "".VHD"" OR filename CONTAINS "".VMDK"" OR filename CONTAINS "".VMEM"" OR filename CONTAINS "".VMSD"" OR filename CONTAINS "".VMSN"" OR filename CONTAINS "".VMSS"" OR filename CONTAINS "".VMTM"" OR filename CONTAINS "".VMTX"" OR filename CONTAINS "".VMX"" OR filename CONTAINS "".VMXF"" OR filename CONTAINS "".VSD"" OR filename CONTAINS "".VSDX"" OR filename CONTAINS "".VSWP"" OR filename CONTAINS "".WAR"" OR filename CONTAINS "".WB2"" OR filename CONTAINS "".WK1"" OR filename CONTAINS "".WKS"" OR filename CONTAINS "".XHTML"" OR filename CONTAINS "".XLC"" OR filename CONTAINS "".XLM"" OR filename CONTAINS "".XLS"" OR filename CONTAINS "".XLSB"" OR filename CONTAINS "".XLSM"" OR filename CONTAINS "".XLSX"" OR filename CONTAINS "".XLT"" OR filename CONTAINS "".XLTM"" OR filename CONTAINS "".XLTX"" OR filename CONTAINS "".XLW"" OR filename CONTAINS "".YML"" OR filename CONTAINS "".ZIP"") | RARE filename
```
```text
The following query detects activity related to removing the Defender directory leveraging powershell.exe
```
```text
rg_functionality = ""Endpoint Management Systems"" AND sourceprocessname = powershell.exe AND (resourcecustomfield1 CONTAINS ""rmdir 'C:\ProgramData\Microsoft\Windows Defender” OR resourcecustomfield3 CONTAINS ""rmdir 'C:\ProgramData\Microsoft\Windows Defender'"")"
```
```text
The following query detects the activity of removing traces of activity performed using cmd.exe and specific command line parameters.
```
```text
rg_functionality = ""Endpoint Management Systems"" AND sourceprocessname = cmd.exe AND (resourcecustomfield1 CONTAINS ""Del /f /q"" OR resourcecustomfield3 CONTAINS ""Del /f /q"") | RARE resourcecustomfield1"
```




__Antivirus / Malware / EDR__:

__Cloud Antivirus / Malware / EDR__:

__Microsoft Windows__:

__Web Proxy__:

__Next Generation Firewall__:
