#!/usr/env python

import time
import json
import sys
import io
import socket
import csv
from urllib import urlopen
#from netaddr import IPNetwork, IPAddress
#from netaddr import *

reload(sys)
sys.setdefaultencoding('utf8') #set encoding

if len(sys.argv) < 2:
    print ('*** GEO IP LOOKUP TOOL ***')
    print ('[*] Rudi Peck - www.g-cpartners.com with Ddym additions 6/25')	
    print ('Ddym rewrite 8/30')	
    print ('[*] Usage: python iplookup.py ListWithIPs.csv')
    
    exit(0)
else:
    iplist = sys.argv[1]
    spos = sys.argv[2]

whois_cache = []
fqdn_cache = []
spos = int(spos)
fireholelist = []

def GetFireHoleList():
    url = "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
    fireholeraw = urlopen(url).read()
    fireholeraw = fireholeraw.split("\n")

    with open('fireholelist.txt','w') as outFHfile:
        for line in fireholeraw:
            if not line.startswith("#"):
                    outFHfile.write(line +"\n")

def CheckFireHoleList(ip):
    #https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python-2-x
    with open('fireholelist.txt','r') as inF:
        for line in inF:
            if ip in line:
                return "FH hit"
        else:
            return ""

def isItIP(addr):
    try:
        #pattern = re.compile(r'.[0-9]\$,')
        #if pattern.findall(s):
        socket.inet_aton(addr)
            #if len(addr) > 6:
        return True
    except socket.error:
        return False

def GetHostname(ip):
    hostdns = ""
    try:
        found = 0
        if len(fqdn_cache) > 0:
            for row in fqdn_cache:
                if ip in row:
                    found = 1
                    hostdns = row
        if found == 0:
            #hostdns - IPAddress(ip).reverse_dns
            #if not common.private_ips_regex.match(addr.get_addr(ip)):
            data = socket.gethostbyaddr(ip)
            hostdns += repr(data[0])
            fqdn_cache.append(hostdns)
        return hostdns
    except:
        return hostdns

def GetWhois(ip):
    GeoInfo = ""
    try:
        found = 0
        if len(whois_cache) > 0:
            for row in whois_cache:
                if ip in row:
                    found = 1
                    GeoInfo = row
        if found == 0:
            chkAddress = "http://pro.ip-api.com/json/" + ip + '?key=OyLXtLX41aYZ2P1'   #Build Query String
            #print chkAddress
            ipquery = urlopen(chkAddress).read()             #Query IP Address
                
            ipresults = json.loads(ipquery)            #load json result
            GeoInfo += ip + " ("
            #GeoInfo +=ipresults["country"] + ", "
            GeoInfo +=ipresults["country"] + ", "
            # GeoInfo +=ipresults["isp"] + ", "
            # GeoInfo +=ipresults["as"]  + ", "
            GeoInfo +=ipresults["org"]  
            
            #add to local cache so we don't do double lookups
            whois_cache.append(GeoInfo)
        
        return GeoInfo
    except:
        GeoInfo = ip + "(-"
        return GeoInfo
    return ip

#GetFireHoleList()

#Process IP List
with open(iplist, "rb") as f:
    #sniffer = csv.Sniffer()
    #dialect = sniffer.sniff(iplist[1])
    #f.seek(0)
    reader = reader = csv.reader(f, delimiter=',', quoting=csv.QUOTE_MINIMAL)

    newRow = ""
    for row in reader:
        newRow = ""
        icount = 0
        for item in row:
            #if isItIP(item):
            if icount == spos:
                #newRow += item + " ("
                whois = GetWhois(item)
                if whois:
                    newRow += whois
                else:
                    newRow += item + " ("
                
                hostName = GetHostname(item)
                if hostName:
                    newRow +=  " [" + hostName + "]"
    
                #flCheck = CheckFireHoleList(item)
                #if flCheck:
                #    newRow += " | " + flCheck
                
                newRow += ")"
                newRow += "\t"
            else:
                newRow += item +"\t"
            icount = icount + 1
            
        #allow for ctrl+c
        #time.sleep(1)

        print newRow.rstrip("\t")

