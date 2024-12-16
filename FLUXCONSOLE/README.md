
## IOCs

__domain__:

```text
siasat.top
```
__hash__:

```text
b3b2d915f47aa631cc4900ec56f9b833e84d20e850d78f42f78ad80eb362b8fc
b33d76c413ef0f4c48a8a61cfeb5e24ff465bbc6b70bf0cada2bb44299a2768f
f6c435a9a63bdef0517d60b6932cb05a8af3b29fc76abafc5542f99070db1e77
5756f6998e14df4dd09f92b9716cffa5cd996d961b41b82c066f5f51c037a62f
```
__url__:

```text
https://ewh.ieee.org/reg/ccece15/files/ccece-word-sample.pdf
```
__spotterqueries__:

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "File created" OR deviceaction = "File created (rule: FileCreate)") AND customstring49 ENDS WITH "\\ProgramData\\Dism.exe"
rg_functionality = “Endpoint Management Systems” AND (deviceaction = “Process Create” OR deviceaction = “Process Create (rule: ProcessCreate)” OR deviceaction = “ProcessRollup2” OR deviceaction = “Procstart” OR deviceaction = “Process” OR deviceaction = “Trace Executed Process”) AND customstring49 ENDS WITH "\\ProgramData\\Dism.exe"
```