#!/usr/env python

import time
import json
import sys
import io
import socket
import csv
import apilityio
from urllib import urlopen
#from netaddr import IPNetwork, IPAddress
#from netaddr import *

reload(sys)
sys.setdefaultencoding('utf8') #set encoding

delim = ","
#delim = "\t"

if len(sys.argv) < 3:
    print ('*** GEO IP LOOKUP TOOL ***')
    print ('Ddym rewrite v4d 10/26/18')
    print ('[*] Usage for csv headers: python iplookup.py ListWithIPs.csv')
    print ('[*] Usage to process: python iplookup.py ListWithIPs.csv <#>')
    
    #exit(0)
    #enumerate header so we know what column # to pass in to the script
    with open(sys.argv[1], "rb") as f:
        reader = csv.reader(f, delimiter=delim, quoting=csv.QUOTE_MINIMAL)
        iH = 0
        for row in reader:
            print "\r\n#\tColumn"
            print "----\t---------------"
            for col in row:
                print str(iH) + "\t" + col
                iH = iH +1
            sys.exit()
    exit(0)
else:
    iplist = sys.argv[1]
    spos = sys.argv[2]

whois_cache = []
fqdn_cache = {}
spos = int(spos)
fireholelist = []
blacklist = {}

client = apilityio.Client(api_key="5e51cb2e-90e4-4f73-b8f7-1f73f513e4d5")

def CheckIPapilityio(ip):
    if len(blacklist) > 0:
        for key, value in blacklist.iteritems():
            if ip == key:
                return value

    response = client.CheckIP(ip)

    if response.status_code == 404:
        blacklist[ip] = ""
        return ""
        #print("Congratulations! The IP address has not been found in any blacklist.")
    if response.status_code == 200:
        #print("Ooops! The IP address has been found in one or more blacklist")
        blacklists = response.blacklists
        flatlist = ", ".join(blacklists)
        blacklist[ip] = flatlist
        return flatlist
        #print('+- Blacklists: %s' % blacklists)

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

#def SaveLists():


GetFireHoleList()

#Process IP List
with open(iplist, "rb") as f:
    #sniffer = csv.Sniffer()
    #dialect = sniffer.sniff(iplist[1])
    #f.seek(0)
    reader = reader = csv.reader(f, delimiter=delim, quoting=csv.QUOTE_MINIMAL)

    newRow = ""
    for row in reader:
        newRow = ""
        icount = 0
            
        for item in row:
            #if isItIP(item):
            if icount == spos:                
                # now the good stuff
                fqdn  = GetHostname(item)
                newRow += fqdn + " "
                
                flCheck = CheckFireHoleList(item)
                if flCheck:
                    newRow += flCheck
                    
                #newRow += item + " ("
                whois = GetWhois(item)
                if whois:
                    newRow += whois + "\t"
                
                #hostName = GetHostname(item)
                #if hostName:
                #    newRow +=  " [" + hostName + "]"
                
                #newRow += ")"
                newRow += "\t"
            else:
                newRow += item +"\t"
            
            icount = icount + 1
            
        #allow for ctrl+c
        #time.sleep(1)

        print newRow.rstrip("\t")

