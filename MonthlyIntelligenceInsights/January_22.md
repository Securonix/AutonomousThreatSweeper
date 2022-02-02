## SysJoker Backdoor

__Microsoft Windows__:
```text
This query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”
```

```text
index=activity and rg_functionality = "Microsoft Windows'' and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath

```
__Antivirus / Malware / EDR__:
```text
This query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”
```

```text
index=activity and rg_functionality = "Antivirus / Malware / EDR" and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2
```

```text
This query detects the registry modification in the below registry path post execution.
```

```text
index=activity and rg_functionality = "Antivirus / Malware / EDR" and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2

```

__Cloud Antivirus / Malware / EDR__:
```text
This query looks for rare files downloaded and executed in mentioned directories where the backdoor has been observed to operate
```

```text
index=activity and rg_functionality = "Microsoft Windows" and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath
```

```text
This query detects the registry modifications for persistence.
```

```text
index=activity and rg_functionality = "Cloud Antivirus / Malware / EDR" and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2
```
__Endpoint Management Systems__:
```text
This query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”
```

```text
index=activity and rg_functionality = "Microsoft Windows" and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath
```

```text
This query detects the registry modification to maintain persistence.
```

```text
index=activity and rg_functionality = “Endpoint management Systems” and devicecustomstring2 CONTAINS ““HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run” | RARE customstring2
```

## WhisperGate Malware

__Endpoint Management Systems__:
```text
This query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”
```

```text
index=activity and rg_functionality = "Microsoft Windows'' and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath

```
