#!/usr/env python
import os
import time
import json
import sys
import io
import pickle
import socket
import json
from pathlib import Path
import geoip2.database
import requests
from netaddr import IPNetwork, IPAddress

#Updated for python3

#sys.setdefaultencoding('utf8') #set encoding

#provide text file with list of ip's
iplist = sys.argv[1]

whois_cache = []
fqdn_cache = {}
firehole_list = []
firehole_anon = []
firehole_proxies = []

def writeFQDNcache():
    with open('fqdnCache.txt', 'wb') as handle:
        pickle.dump(fqdn_cache, handle)

def loadFQDNcache():
    if os.path.exists("fqdnCache.txt"):
        with open('fqdnCache.txt', 'rb') as handle:
            fqdn_cache = pickle.loads(handle.read())

def CheckFQDN(ip):
    hostdns = ""
    try:
        if ip in fqdn_cache:
                return fqdn_cache.get(ip)
        else:
            data = socket.gethostbyaddr(ip)
            if repr(data[0]):
                hostdns = repr(data[0])
            else:
                hostdns = "NA"
            
            fqdn_cache[ip]=hostdns
    except:
        hostdns = ""
    return hostdns

def getInfo(IP,readerCity):
    response = readerCity.city(IP)
    result = []
    
    result.append(IP)

    try:
        if(response.city.name):
            result.append(response.city.name)
        else:
            result.append("\"\"")
        if(response.country.name):
            result.append(response.country.name)
        else:
            result.append("\"\"")
        try:
            with geoip2.database.Reader('/mnt/d/ddym/Dropbox/GeoLite2-ASN_20200609/GeoLite2-ASN.mmdb') as reader:
                response = reader.asn(IP)
                if(response.autonomous_system_organization):
                    result.append("\"" + response.autonomous_system_organization.replace(","," ") + "\"")
                else:
                    result.append("\"\"")
        except:
            result.append("\"\"")
    except:
        result.append("\"\"")

    return ",".join(result)

def GetFireHoleLists(outFilename,strUrl,fList):
    my_file = Path(outFilename)
    if not my_file.exists():
        print("fetching firehole list: " + outFilename)
        url = strUrl
        r = requests.get(url, allow_redirects=True)
        fireholeraw = r.content.decode()

        with open(outFilename,'w') as outFHfile:
            for i, line in enumerate(fireholeraw):
                outFHfile.write(line)
    with open(outFilename,'r') as inF:
        fList.clear()

        for line in inF:
            fList.append(line)

def CheckFireHoleList_cidr(ip,flist,strMessage):
    #https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python-2-x
    for ncidr in flist[35:]:
        try:
            if IPAddress(ip) in IPNetwork(ncidr.rstrip()): 
                return strMessage
        except:
            print(ncidr)
    return ""

GetFireHoleLists("fireholelist.txt","https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",firehole_list)
GetFireHoleLists("fireholelist_anon.txt","https://iplists.firehol.org/files/firehol_anonymous.netset",firehole_anon)
GetFireHoleLists("fireholelist_proxies.txt","https://iplists.firehol.org/files/firehol_proxies.netset",firehole_proxies)
loadFQDNcache()

print("IP, City, Country, ASN Org, hostname, FireHole Indicators")

with open(iplist, "r") as f:
    readerCity = geoip2.database.Reader('/mnt/d/ddym/Dropbox/GeoLite2-City_20200609/GeoLite2-City.mmdb')

    for ip in f:
        newRow = ""
        icount = 0
        row = getInfo(ip.rstrip(),readerCity)
        #dns = CheckFQDN(ip.rstrip())
        fh = CheckFireHoleList_cidr(ip.rstrip(),firehole_list,"level 1")

        #if dns:
        #    row += "," + dns
        
        fhresult = ""
        if fh:
            fhresult += fh + "|"
        if ip in firehole_anon:
            fhresult += "anonymous|"
        if ip in firehole_proxies:
            fhresult += "proxies"

        if fhresult:
            row += "," + fhresult.rstrip("|")

        print (row)

# save fqdn cache
writeFQDNcache()