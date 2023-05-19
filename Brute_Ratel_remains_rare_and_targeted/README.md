
## IOCs

__domain__:

```text
prefectrespond.online
instrumentation-database-fc-lows.trycloudflare.com
```
__ipaddress__:

```text
5.78.50.172
```
__hash__:

```text
f31d785e7dc5d715a768d0d9565488cbeeb9ab35e4a0895785ecea533692176a
4a8495f03644db7a08d5a995b4f373eff2ade8e61261fb4818ac0bb9da7b0540
f86770a368d75ece9b8542e3087218c01676c0444e18d5d68f53902619049462
f1087f4eff735123ec5ec7fe67b11208c73fc49110bde60cecd42f1a10ed9c89
88908f7a8834ba08a69403af99aca50f61cb8c571fe6b50046ccba5b146f5a45
fe010ed0549c00326f4319c1ac2d16684957a2fd09e0c7bbfec55e92f5d8606c
d5b0c42ef9642dce715b252a07fc07ad9917bfdc13bd699d517b78210cc6ec60
```
__spotterqueries__:

```text
rg_functionality="Next Generation Firewall" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "prefectrespond.online" OR destinationhostname CONTAINS "instrumentation-database-fc-lows.trycloudflare.com")
rg_functionality="Firewall" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "prefectrespond.online" OR destinationhostname CONTAINS "instrumentation-database-fc-lows.trycloudflare.com")
rg_functionality="Web Proxy" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "prefectrespond.online" OR destinationhostname CONTAINS "instrumentation-database-fc-lows.trycloudflare.com")
```