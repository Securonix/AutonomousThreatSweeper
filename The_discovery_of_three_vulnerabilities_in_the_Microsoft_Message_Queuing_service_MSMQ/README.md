
## IOCs

__spotterqueries__:

```text
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Network connection detected" OR deviceaction = "Network connection detected (rule: NetworkConnect)") AND (destinationprocessname = "mqsvc.exe" OR destinationport = "1801")
rg_functionality = "Microsoft Windows" and baseeventid = 4688  and destinationprocessname = "mqsvc.exe" | STATS resourcename
rg_functionality = "Endpoint Management Systems" AND (deviceaction = "Process Create" OR deviceaction = "Process Create (rule: ProcessCreate)" OR deviceaction = "ProcessRollup2" OR deviceaction = "Procstart" OR deviceaction = "Process" OR deviceaction = "Trace Executed Process") AND destinationprocessname = "mqsvc.exe" | STATS sourcehostname
```