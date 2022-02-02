## SysJoker Backdoor

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
