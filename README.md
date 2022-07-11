# log4j_masscan_validator
A basic log4shell vulnerability scanner to determine if log4shell can potentially be exploited within a set of IPs collected via masscan, obviously this is not to be used for malicious or illegal purposes, only for scanning your own subnets or those you have permison to scan

This scanner is use at own risk, its super basic kinda janky and likely will fail offering only a false sense of security. Other tests can be added or removed as new or better info is released

There is currently one filter removing IIS hosts, further filters can be added as required

USAGE: `scan.py path/to/masscan/output`
