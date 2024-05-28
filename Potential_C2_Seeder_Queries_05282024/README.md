
## IOCs

__spotterqueries__:

```text
rg_functionality="Next Generation Firewall" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "foundationforwomenshealth.com" OR destinationhostname CONTAINS "jlmin.cc" OR destinationhostname CONTAINS "imagedownload.ignorelist.com")
rg_functionality="Web Application Firewall" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "foundationforwomenshealth.com" OR destinationhostname CONTAINS "jlmin.cc" OR destinationhostname CONTAINS "imagedownload.ignorelist.com")
rg_functionality="DNS / DHCP" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "foundationforwomenshealth.com" OR destinationhostname CONTAINS "jlmin.cc" OR destinationhostname CONTAINS "imagedownload.ignorelist.com")
rg_functionality="Web Proxy" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "foundationforwomenshealth.com" OR destinationhostname CONTAINS "jlmin.cc" OR destinationhostname CONTAINS "imagedownload.ignorelist.com")
rg_functionality="Firewall" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "foundationforwomenshealth.com" OR destinationhostname CONTAINS "jlmin.cc" OR destinationhostname CONTAINS "imagedownload.ignorelist.com")
rg_functionality="IDS / IPS / UTM / Threat Detection" AND destinationhostname NOT NULL AND (destinationhostname CONTAINS "foundationforwomenshealth.com" OR destinationhostname CONTAINS "jlmin.cc" OR destinationhostname CONTAINS "imagedownload.ignorelist.com")
rg_functionality="Next Generation Firewall" AND ipaddress NOT NULL AND ipaddress IN ("43.247.134.248", "138.68.79.95")
rg_functionality="Firewall" AND ipaddress NOT NULL AND ipaddress IN ("43.247.134.248", "138.68.79.95")
rg_functionality="Web Proxy" AND ipaddress NOT NULL AND ipaddress IN ("43.247.134.248", "138.68.79.95")
rg_functionality="Web Application Firewall" AND ipaddress NOT NULL AND ipaddress IN ("43.247.134.248", "138.68.79.95")
rg_functionality="DNS / DHCP" AND ipaddress NOT NULL AND ipaddress IN ("43.247.134.248", "138.68.79.95")
rg_functionality="IDS / IPS / UTM / Threat Detection" AND ipaddress NOT NULL AND ipaddress IN ("43.247.134.248", "138.68.79.95")
```