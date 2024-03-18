
## IOCs

__domain__:

```text
gbionet.com
```
__hash__:

```text
f262588c48d2902992ffd275d2be6362fe7f02e2f00a44ab8c75ac1a2827c6e9
1617587ccdf5b0344089559ecf8fe7d39f6e07a6a64f74f2b44bfa2c8cb67983
46a5d54c264152ce915792af31c75824a558af7d7340d78b34e146d8c6249e79
1b75f70c226c9ada8e79c3fdd987277b0199928800c51e5a1e55ff01246701db
69c917ea96db28dbd5b67073ca0aac234d25651a849171b45f20979eafa05a1c
60666cacdd6806ed05771f32eaa719e3efd2f4db55f28a447d383c3eac1dc72e
b72caab78d164637fea0937d7a94fc470579ec6bb4fa87dadb6f0fa7826e217c
89cad9a57985cc0ab3b7403a943ad0aa7b167dc7a3c38557417fedea67a77b87
```
__url__:

```text
https://content.dropboxapi.com/2/files/download/step2/ps.bin
https://content.dropboxapi.com/2/files/download/step2/r_enc.bin
https://content.dropboxapi.com/2/files/download/step2/info_sc.txt
https://content.dropboxapi.com/2/files/download/step2/info_ps.bin
https://content.dropboxapi.com/2/files/download/step2/ad_ps.bin
https://content.dropboxapi.com/2/files/download/step2/info_sc.txt
```

__spotterquery__:

```text
index = activity AND rg_functionality=”Next Generation Firewall” AND requesturl CONTAINS “content.dropboxapi.com/2/files/download/step2/” AND (requesturl CONTAINS “ps.bin” OR requesturl CONTAINS “r_enc.bin” OR requesturl CONTAINS “info_sc.txt” OR requesturl CONTAINS “info_ps.bin” OR requesturl CONTAINS “ad_ps.bin”)
index = activity AND rg_functionality = “Endpoint Management Systems” AND (deviceaction = “File created” OR deviceaction = “File created (rule: FileCreate)”) AND customstring49 ENDS WITH “Appdata\Microsoft\Windows\Themes\version.xml”
index = activity AND rg_functionality = “Microsoft Windows Powershell” AND (message CONTAINS “content.dropboxapi.com/2/files/download” OR message CONTAINS “content.dropboxapi.com/2/files/upload”)
index = activity AND rg_functionality = “Endpoint Management Systems” AND (deviceaction = “File created” OR deviceaction = “File created (rule: FileCreate)”) AND customstring49 CONTAINS “\AppData\Local\Temp\” AND customstring49 CONTAINS “.zip” AND customstring49 ENDS WITH “.lnk”
```
