
## IOCs

__domain__:

```text
telemistry.net
ukmedia.store
windowsupdatebg.s.llnwi.net
```
__ipaddress__:

```text
95.179.201.171
95.179.180.224
172.86.75.75
95.179.186.167
95.179.170.76
193.149.187.170
193.149.185.229
```
__hash__:

```text
36bf06bde63af8cdd673444edf64a323195fe962b3256e0269cdd7a89a7e2ae1
631f92c9147733acf3faa02586cd2a6cda673ec83c24252fccda1982cf3e96f6
d496394abba570aa86abb4238cfa03762e3ccdb5c14920e3669ec2c1bb06321b
36bf06bde63af8cdd673444edf64a323195fe962b3256e0269cdd7a89a7e2ae1
13140291db39218c897d2ff960c1ef4ec3107bd239bc04ba8a218ad3b4dbd72f
4ba964764210607f3bab884a14afa0b917891cff969a309bbbc12d3321386352
bfe048ba91218019b64ab8477dad3ba6033cbc584f0d751d2866023b2b546c2e
d95e19341fa4af9a405f3a34fc3788dd9b74a9d6ab0f5cbe63cca5271ce63e05
7ac84bf51b9db169b1282bb40daae2d38bb2fa5acc02b590198815a79cee1dbf
47e5232576e2eed33a13bca998c93e7aee57711f588b17f75367f7e58ea09ad9
494839430932a97030a7163d636d2365d715ff517ba912f2afd0c557494d077a
debead9e8e3d106991e38d2057931265b3a08d4746c08255df0a4bf986327215
7358d711f27086a21ce7485b1f1a570f0556f2c4096e22cac94a4b5d86842194
1e8c661f7496120d66aaca02def8c670f1bd656f0e9f4aefb5991bf214a48ffc
1c9cd406024034cd69ac881801085b21864ec4148dd9cab6498cbd7ca77408bc
5eee027839ce7f97976af005c04ff5d22316eacd2cd880b95f6bdb09ee84fd5c
debead9e8e3d106991e38d2057931265b3a08d4746c08255df0a4bf986327215
1f03769fc692886f1dbdf2a2cfe7be50e6cbe94fb364ca4a0f501e88bd1ccb3
b9c08b08d5a97c93db572fe67fcee129a41235182d9a6be8164058da0969ece9
13275de2ee18d0b66772dec7ad5d1f2eb16875de8b33802793bcf4a5b41c7432
6e90de5bf00945252fcfc3746446b5d1037af59bed67e6e33de1a5dae9616bf9
```
__url__:

```text
http://95.179.201.171/robots.php
http://95.179.180.224/robots.php
httx://172.86.75.75/robots.php
http://95.179.186.167/writer.php
http://193.149.185.229/sas.php
http://ukmedia.store/static-directory/html.mp3
http://193.149.185.229/api/sharpchrome.exe
http://telemistry.net/get.php?id=xxxxxxx
```
__spotterqueries__:

```text
rg_functionality = “Endpoint Management Systems” AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND destinationprocessname ENDS WITH “typeperf.exe” AND resourcecustomfield1 CONTAINS “\system\processor queue length” AND resourcecustomfield1 CONTAINS ” -si ” AND resourcecustomfield1 CONTAINS ” -sc “
rg_functionality = “Endpoint Management Systems” AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND (destinationprocessname ENDS WITH “msxsl.exe” OR filename = “msxsl.exe”) AND (resourcecustomfield8 CONTAINS “\Appdata\Local\” OR resourcecustomfield8 CONTAINS “\Appdata\Roaming\” OR resourcecustomfield8 CONTAINS “\ProgramData\” OR resourcecustomfield8 CONTAINS “\Users\Public\” OR filename = “msxsl.exe”) AND destinationprocessname NOT ENDS WITH “msxsl.exe”
rg_functionality = “Endpoint Management Systems” AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND (((destinationprocessname ENDS WITH “ie4uinit.exe” OR filename = “IE4UINIT.EXE”) AND resourcecustomfield8 NOT CONTAINS “Windows\System32” AND resourcecustomfield8 NOT CONTAINS “Windows\SysWOW64”) OR (filename = “IE4UINIT.EXE” AND destinationprocessname NOT ENDS WITH “ie4uinit.exe”))
rg_functionality = “Endpoint Management Systems” AND (deviceaction = “Process Create” OR deviceaction = “ProcessCreate” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “SyntheticProcessRollUp2” OR deviceaction = “WmiCreateProcess” OR deviceaction = “Trace Executed Process” OR deviceaction = “Process” OR deviceaction = “Childproc” OR deviceaction = “Procstart” OR deviceaction = “Process Activity: Launched”) AND destinationprocessname ENDS WITH “wmic.exe” AND resourcecustomfield1 CONTAINS “process” AND resourcecustomfield1 CONTAINS “call” AND resourcecustomfield1 CONTAINS “create”
rg_functionality = “Endpoint Management Systems” AND (destinationprocessname ENDS WITH “curl.exe” OR destinationprocessname ENDS WITH “wget.exe”) AND (resourcecustomfield1 CONTAINS “.jpg” OR resourcecustomfield1 CONTAINS “.jpeg” OR resourcecustomfield1 CONTAINS “.png”) AND (resourcecustomfield1 CONTAINS “http://” OR resourcecustomfield1 CONTAINS “https://”)
(rg_functionality = “Next Generation Firewall” OR rg_functionality = “Web Application Firewall” OR rg_functionality = “Web Proxy”) AND (destinationaddress = “95.179.201.171” OR destinationaddress = “95.179.186.167” OR destinationaddress = “95.179.170.76” OR destinationaddress = “193.149.187.170” OR destinationaddress = “193.149.185.229”)
```