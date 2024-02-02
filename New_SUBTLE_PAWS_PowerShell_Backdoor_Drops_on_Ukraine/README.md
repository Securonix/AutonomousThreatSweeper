
## IOCs

__domain__:

```text
guvalas.ru
```
__ipaddress__:

```text
185.245.184.146
195.133.88.136
81.19.140.172
85.159.228.101
89.185.84.203
92.118.112.195
```
__hash__:

```text
252a6736420862db7a275a16f5c3d4f3e51784244ccf72fcfa30236439d834c8
61370d0ac56f73321c11876424ec75e2740d6910ff53b0791f0560c72d85b330
2861ce32762327228f9875643ab253e2c2b04565739b65919d2afdde405a9aea
d222977ab20317647595c9de7413bd17a8074006007150102aa2b569fc2ccbf1
3a4c14d0745fc97839f904bacb8b42fd9eb620d736a29c08841a2e9c0e488d3b
6dded7fc8b22bfce6f7c548d75b20f01586d348982788626178d48c72d705e26
eec752c82a84c1a5bc949fdd6fe23d70c8837a03184aa89a1e9698c730a51582
b22e3f12a8c41096d83da3f9e04931afe60a7bb182261861569858e3d50967ca
8f9ad0ad2ba5499caf098c3dc055888883d1268257cf923a380e7c3460f1c63d
c44acd1b6961d585e89366d0fe0c2dac3fd6103318ec8feba3e4926c85b85a02
7c480891587f22cd8592cc4e9dd2f10d907e02cf46d6b4c188adb13669ab3aec
3bc1afed855dbd8c729c50a74dfe01164673941ddf8dcaf4402d9b23edc2f2cc
8ece5d5c77c3a03b50c756f39b9212956143b969223318530a8dbb9f3d9f5f3d
e7e9d09e181901fe7f2fee367ab9b7e6ae05150e3ee01046f370078911ab215c
029c0f4c44da0733ec6455abdd120faba7fc7989489c3fe7cec86c25bad3e572
d7e228473690fec029a0204feb2ae58504a869c86686194b8034c21718a55be7
038fa00486ebe8a4f22f167fd664acc41d59334489a920f7f24cad2910cf3417
3678034e693e3451754401c1b71d841dc8dcd63ea2dd9343fe52c81fd056d519
5856e52224ec2c7d322fe28e207a8aef5d7b69032ed060fbd1ead7331f67a004
9d1f858d2325a27944a21387b78fa3957b904325350e580e8de5255aa650cb1d
3aad467c86dba8755e6f5209307cd311ab6f517f26578144e3c7b16308177d83
6edc9b3ff9f69e86919d80b513e7ca4c93ac0dc03d6e40f85a8703ff49da2758
8102995258f1d800a76273213ae57b3a320cbafed491c101db5eb7b191ce53d7
3063d671609088bb518ff69fdec337edd1ba5626bd427e03ed8d9d0f8ea4f14f
79c2038b401391923c4253a5409ae537e8d397c8dfe8510b9c467be78ca04f59
5302e764a9638d86f787137ed02d6c59a4e1e6aa2e7bee27ec91653c83e3127a
2f0375bb6a732010d0082f0f44f74d6a641e0a61c9f77d7922a15597cda6a1cd
7a925d78c3b0f30b16ee358eec51f2a6439027bdf37b1c840dbc49ff1b224054
c32844822c46d76e39afd825348ab07d45cc6015a544debdf0c39a438d66006b
aa01b0cc318286ed4db10b23d2a3cd27482ef2b0df794234f62e2d59cfc67336
920bd70612e63c673ce3b84b4a1fc7319c2fb01fa940d8a269429ff8fdd5d018
17752b3f3b452acaf372108cc233ca67790ff62716916a9b84b4e3ef31e89883
ed891f921f379916f6119c32dafd068b13b216d11ab8f212bd309ef39f24d0de
462be856bf70bc25df2a694825d99b97453f117100a3309df3c03b1fc60eaa61
ec6283e87abc73cdf0af2120a77ea3140904b261d61782369b9a25431aee9ebf
52b7243b9c07a51dabb3dc69216adb6e277acffa827d2599c68c331adee8feaf
bf754818c4033247f645c66e7a61e6e755795982339e74011857c79ef17f391d
5e7aad698dc49213ce6c9a1b2dcfccc3f42769855d5169d41baf99b46d405ad0
c0a01267184fc943d6c5d373341fd495ecf6d69154343e3980a11635446d522f
19ccdb29f65b6bd79e536fcd3560874d8a725730bf24365ca9695c0322bb33d8
02459f35033d241a71124051153890ca8d3470aebce07446cf6e16d5757b51f1
6cad4614e91980af16f9057764f98fb44ca2fa99ddcff46b76297b3c8cd0be0
4ec3682bc45036a0c48c01208ec1fb07b8af6d9f03ac803a51b34876b3be245e
b257088c0d3ca65f3a3bda1b8cecf942d0967f3591e182ec32474737ab6bf3c6
02a29c72c2b6b9ae4359743ac10c232668a51f330799b902b32989769768e84a
5460cbebc25fe4c856afc5089702afaa90edcbc25c4980e021d1c59bf4e059ea
```
__url__:

```text
https://telegra.ph/home-11-29-16
https://telegra.ph/osnmbfjr1h-09-07
https://telegra.ph/j7bl93kg8t-07-18
https://telegra.ph/25mct8ogil-08-21
```
__spotterqueries__:

```text
index = activity AND rg_functionality = “Microsoft Windows Powershell” AND (message CONTAINS “gc ” OR message CONTAINS “Get-Content “) AND message CONTAINS “|” AND message CONTAINS ” – ” AND message CONTAINS “Out-String” AND message CONTAINS “powershell”
index=activity AND rg_functionality=”Next Generation Firewall” AND destinationaddress IN (“185.245.184.146″,”195.133.88.136″,”81.19.140.172″,”85.159.228.101″,”89.185.84.203″,”92.118.112.195”)
index=activity AND rg_functionality=”Firewall” AND destinationaddress IN (“185.245.184.146″,”195.133.88.136″,”81.19.140.172″,”85.159.228.101″,”89.185.84.203″,”92.118.112.195”)
index=activity AND rg_functionality=”Web Proxy” AND destinationaddress IN (“185.245.184.146″,”195.133.88.136″,”81.19.140.172″,”85.159.228.101″,”89.185.84.203″,”92.118.112.195”)
index = activity AND rg_functionality = “Microsoft Windows Powershell” AND (message CONTAINS “Kropiva” OR message CONTAINS “softwareenvironment816” OR message CONTAINS “segmenttable453”)
index = activity AND rg_functionality = “Microsoft Windows Powershell” AND message CONTAINS “setRequestHeader” AND message CONTAINS “User-Agent”
index = activity AND rg_functionality = “Microsoft Windows Powershell” AND (message CONTAINS “sajb ” OR message CONTAINS “Start-Job”) AND (message CONTAINS “gp ” OR message CONTAINS “Get-ItemProperty”) AND (message CONTAINS “iex ” OR message CONTAINS “Invoke-Expression”) AND (message CONTAINS “HKCU:\” OR message CONTAINS “HKLM:\”)
index = activity AND rg_functionality = “Endpoint Management Systems” AND (deviceaction = “File created” OR deviceaction = “File created (rule: FileCreate)”) AND customstring49 CONTAINS “\AppData\Winword\”
index = activity AND rg_functionality = “Endpoint Management Systems” AND (baseeventid = “12” OR baseeventid = “13” OR baseeventid = “14”) AND transactionstring5 = “SetValue” AND ((customstring47 CONTAINS “\System\pyrolyzing505” OR customstring47 CONTAINS “\System\softwareenvironment816” OR customstring47 CONTAINS “\System\prepare” OR customstring47 CONTAINS “\System\run” OR customstring47 CONTAINS “\System\save” OR customstring47 CONTAINS “\System\search” OR customstring47 CONTAINS “\System\SetLnk” OR customstring47 CONTAINS “\System\executer” OR customstring47 CONTAINS “\System\result_code”) OR (customstring47 CONTAINS “\System\” AND (customstring48 CONTAINS “Get-ItemProperty” OR customstring48 CONTAINS ” -bxor ” OR customstring48 CONTAINS “MSXML2.XMLHTTP”)))
```