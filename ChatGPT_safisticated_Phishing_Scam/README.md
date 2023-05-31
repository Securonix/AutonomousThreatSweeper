
## IOCs

__domain__:

```text
ipfs.dweb.link
```
__url__:

```text
https://bafybeidqi4sn5nfnfxlgasem4gsdmbq6m55iu6gtouomdgfwu4fx7ps7oq.ipfs.dweb.link/login.htm
https://bafybeidqi4sn5nfnfxlgasem4gsdmbq6m55iu6gtouomdgfwu4fx7ps7oq.ipfs.dweb.link/login.htm#b@inky.com
```
__spotterqueries__:

```text
rg_functionality="Next Generation Firewall" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "bafybeidqi4sn5nfnfxlgasem4gsdmbq6m55iu6gtouomdgfwu4fx7ps7oq.ipfs.dweb" OR destinationhostname CONTAINS "ipfs.dweb. link")
rg_functionality="Web Proxy" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "bafybeidqi4sn5nfnfxlgasem4gsdmbq6m55iu6gtouomdgfwu4fx7ps7oq.ipfs.dweb" OR destinationhostname CONTAINS "ipfs.dweb. link")
rg_functionality="Firewall" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "bafybeidqi4sn5nfnfxlgasem4gsdmbq6m55iu6gtouomdgfwu4fx7ps7oq.ipfs.dweb" OR  destinationhostname CONTAINS "ipfs.dweb. link")
```