
## IOCs

__ipaddress__:

```text
159.65.42.223
```
__hash__:

```text
b0e13f7370b44797c5c05291a3b03f280286263083d2f7c719defbdd55b42dcb
a36c8ea0188ddc3ed8f06c8e352bb314bc222fef6f9baeb211cd97ac62462dec
418c0706510868bf2afad98bfb66d7492fdb594ca8d477aba89f471ca00d70fd
e1a85757d9a5750078f646461f6bd61dede7236bab90451321ea9b043dcd20f0
d075b86f23ea2f16db1bbbe5d8b141fde60b1655fc48b46335bb8554235bac32
efbb83a531b88d0820d36410356cc4c8deef25deaa8da351a963dd51eadf8048
1b1ee0937147d8867227ea72654d3aa7acb54d5bc1d31b7922586f12a30beeb4
064ee9cc4256a4e004d3c6e74e1a4cc2d686f82a7e22640aa718167b5af40a29
a36c8ea0188ddc3ed8f06c8e352bb314bc222fef6f9baeb211cd97ac62462dec
44737c01c93b96afcbb96c0b38993594d29a0a07d625999ef503c8424da90b0e
```
__spotterqueries__:

```text
rg_functionality="Endpoint Management Systems" AND filehash NOT NULL AND filehash IN ("1b1ee0937147d8867227ea72654d3aa7acb54d5bc1d31b7922586f12a30beeb4","418c0706510868bf2afad98bfb66d7492fdb594ca8d477aba89f471ca00d70fd","064ee9cc4256a4e004d3c6e74e1a4cc2d686f82a7e22640aa718167b5af40a29","d075b86f23ea2f16db1bbbe5d8b141fde60b1655fc48b46335bb8554235bac32","efbb83a531b88d0820d36410356cc4c8deef25deaa8da351a963dd51eadf8048")
rg_functionality="Cloud Antivirus / Malware / EDR" AND filehash NOT NULL AND filehash IN ("1b1ee0937147d8867227ea72654d3aa7acb54d5bc1d31b7922586f12a30beeb4","418c0706510868bf2afad98bfb66d7492fdb594ca8d477aba89f471ca00d70fd","064ee9cc4256a4e004d3c6e74e1a4cc2d686f82a7e22640aa718167b5af40a29","d075b86f23ea2f16db1bbbe5d8b141fde60b1655fc48b46335bb8554235bac32","efbb83a531b88d0820d36410356cc4c8deef25deaa8da351a963dd51eadf8048")
rg_functionality="Antivirus / Malware / EDR" AND filehash NOT NULL AND filehash IN ("1b1ee0937147d8867227ea72654d3aa7acb54d5bc1d31b7922586f12a30beeb4","418c0706510868bf2afad98bfb66d7492fdb594ca8d477aba89f471ca00d70fd","064ee9cc4256a4e004d3c6e74e1a4cc2d686f82a7e22640aa718167b5af40a29","d075b86f23ea2f16db1bbbe5d8b141fde60b1655fc48b46335bb8554235bac32","efbb83a531b88d0820d36410356cc4c8deef25deaa8da351a963dd51eadf8048")
rg_functionality="IDS / IPS / UTM / Threat Detection" AND ipaddress NOT NULL AND ipaddress IN ("159.65.42.223")
rg_functionality="Web Application Firewall" AND ipaddress NOT NULL AND ipaddress IN ("159.65.42.223")
rg_functionality="Next Generation Firewall" AND ipaddress NOT NULL AND ipaddress IN ("159.65.42.223")
rg_functionality="Web Proxy" AND ipaddress NOT NULL AND ipaddress IN ("159.65.42.223")
rg_functionality="DNS / DHCP" AND ipaddress NOT NULL AND ipaddress IN ("159.65.42.223")
rg_functionality="Firewall" AND ipaddress NOT NULL AND ipaddress IN ("159.65.42.223")
```