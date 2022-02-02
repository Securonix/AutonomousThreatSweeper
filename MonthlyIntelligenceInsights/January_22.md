## SysJoker Backdoor

__SHA256 (Phishing Email)__:
```text
be453dcadd408fae5227f8b58f539f3f68aad081c9bf4f2c3dc0ff35c601ef5e
```

__SHA256 (Infected PPAM File)__:
```text
eff2feb50bebb797db7d881a44c549234315a84c861d2bb675899f7165db3ce7
```

__Microsoft Windows__:
```text
This query looks for rare files downloaded and executed in these directories specifically “igfxCUIService.exe”
```

```text
index=activity and rg_functionality = "Microsoft Windows'' and (filepath contains "C:\ProgramData\SystemData" or filepath contains "C:\ProgramData\RecoverySystem") | RARE filename

index=activity and rg_functionality = "Microsoft Windows" and filename CONTAINS "igfxCUIService.exe" | RARE filepath

```

## CryptoCurrency Stealer - Wallet Addresses


__BTC__:
```text
3CghDNiD2J5xsS9i1wzwbvwdTJxokqGCmC
```

__ETH__:
```text
0x8af86e2c7126d08387e71ec6699bc69f957cdee6
```
