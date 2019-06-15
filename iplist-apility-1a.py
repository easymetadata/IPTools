#!/usr/env python

import time
import json
import sys
import io
import socket
import csv
import apilityio
import apilityio.errors
from urllib import urlopen
#from netaddr import IPNetwork, IPAddress
#from netaddr import *

reload(sys)
sys.setdefaultencoding('utf8') #set encoding

if len(sys.argv) < 1:
    print ('*** GEO IP LOOKUP TOOL ***')
    print ('Ddym rewrite v4d 10/26/18')
    print ('[*] Usage for csv headers: python iplookup.py ListWithIPs.csv')
    print ('[*] Usage to process: python iplookup.py ListWithIPs.csv <#>')
else:
    iplist = sys.argv[1]

whois_cache = []
fqdn_cache = {}
fireholelist = []
domainlist = []
blacklist = {}

def CheckIPapilityio(ip):
    rcode = ""
    try:
        ifound = 0
        if len(blacklist) > 0:
            for key, value in blacklist.iteritems():
                if ip == key:
                    if value:
                        print ip + ": " + value
                    ifound = 1
            if ifound > 0:
                return

        #client = apilityio.Client(api_key="5e51cb2e-90e4-4f73-b8f7-1f73f513e4d5")

        #api_key, protocol, host = client.GetConnectionData()
        
        response = client.CheckIP(ip)
        rcode = response.status_code

        if rcode == 404:
            blacklist[ip] = ""
            return
            #print("Congratulations! The IP address has not been found in any blacklist.")
        if rcode == 200:
            #print("Ooops! The IP address has been found in one or more blacklist")
            blacklists = response.blacklists
            if len(blacklists) > 0:
                for item in blacklists:
                    blacklist[ip]=item
                    result = str(ip) + ": " + str(item)
                    print result
    except:
        print "error: " + str(ip) + " [" + str(rcode) + "]"

# #got banned
# def GetBadDomainList():
#     url = "https://www.threatcrowd.org/feeds/domains.txt"
#     domainlist = urlopen(url).read()
#     print domainlist
#     domainlist = domainlist.split("\n")


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
                return "[FH L1]"
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
            for key, value in fqdn_cache.iteritems():
                if found == 0:
                    if ip == key:
                        found = 1
                        hostdns = value
        if found == 0:
            #hostdns - IPAddress(ip).reverse_dns
            #if not common.private_ips_regex.match(addr.get_addr(ip)):
            data = socket.gethostbyaddr(ip)
            hostdns = repr(data[0])
            fqdn_cache[ip]=hostdns
            #fqdn_cache.append(hostdns)
            
        ipfqdn = ip + " [" + hostdns +"]"
        return ipfqdn
    except:
        return ip

def GetWhois(ip):
    GeoInfo = ""
    try:
        found = 0
        if len(whois_cache) > 0:
            for row in whois_cache:
                if found == 0:
                    if ip in row:
                        found = 1
                        GeoInfo = row
        if found == 0:
            #chkAddress = "http://pro.ip-api.com/json/" + ip + '?key=OyLXtLX41aYZ2P1'   #Build Query String
            chkAddress = "http://api.db-ip.com/v2/f6260c4f2abb78756f6e4abed4f25d8dd7e8403a/" + ip    #Build Query String
            #print chkAddress
            ipquery = urlopen(chkAddress).read()             #Query IP Address
                
            ipresults = json.loads(ipquery)            #load json result
            if ipresults:
                GeoInfo += " ("
                #GeoInfo +=ipresults["country"] + ", "
                GeoInfo +=ipresults["countryCode"] + ", "
                #GeoInfo +=ipresults["countryName"] + ", "
                # GeoInfo +=ipresults["isp"] + ", "
                GeoInfo +=ipresults["asName"]
                #GeoInfo +=ipresults["organization"]
                
                #before we go lets check ifProxy or ifthreat is true.. (specific to db-ip api)
                if (ipresults["isProxy"] == "true"):
                    GeoInfo +="{isProxy}"
                if (ipresults["isCrawler"] == "true"):
                    GeoInfo +="{isCrawler}"
                if (ipresults["threatLevel"] != "low"):
                    GeoInfo +="[threatlevel= " + ipresults["threatLevel"] + "]"
                GeoInfo += ")"
            else:
                GeoInfo += "(not found)"
            #add to local cache so we don't do double lookups
            whois_cache.append(GeoInfo)
            
            return GeoInfo
    except:
        GeoInfo = ip
        return GeoInfo
    return GeoInfo

#GetBadDomainList()
#print domainlist
#exit(0)
GetFireHoleList()
client = apilityio.Client(api_key="5e51cb2e-90e4-4f73-b8f7-1f73f513e4d5")

uniqueiplist = []
#Process IP List
with open(iplist, "rb") as f:
#    icount = 0
    for item in f:
        newRow = ""
        #if isItIP(item):
        ip = item.strip()
        uniqueiplist.append(ip)
        # now the good stuff
        #fqdn  = GetHostname(item)
        #newRow += fqdn + " "
            
        #flCheck = CheckFireHoleList(item)
        #if flCheck:
        #    newRow += flCheck
            
        #newRow += item + " ("
        #whois = GetWhois(ip)
        #if whois:
        #    newRow += whois + "\t"
        
#            CheckIPapilityio(ip)
        #apility = CheckIPapilityio(ip)
        #if apility:
        #    newRow += apility + "\t"

        #hostName = GetHostname(item)
        #if hostName:
        #    newRow +=  " [" + hostName + "]"
        
        #newRow += ")"
        #newRow += "\t"

        #icount = icount + 1
        #if icount > 65:
        #    exit(0)
icount = 0
for ip in uniqueiplist:
    #if isItIP(ip):
    CheckIPapilityio(ip)
    icount = icount + 1
    if icount > 10:
        exit(0)
        #else:
            #print ip + ": not ip"
#            newRow += item.strip() +"\t"
        
        #print newRow.rstrip("\t")