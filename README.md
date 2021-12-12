# log4j_masscan_validator
log4j basic vulnrablity scanner for determining if log4j vulnrablity exists within an IP set collected via masscan, obviously this is not to be used for malicious or illegal purposes, only for scanning your own subnets or those you have permison to scan

This scanner is use at own risk, its super basic kinda janky and likely will fail offering only a false sense of security. Other tests can be added or removed as new or better info is released

There is currently one filter of removing IIS hosts, further filters can be added as you see fit

USAGE: scan.py path/to/masscan/output
