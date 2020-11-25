#!/usr/env python
import os
import time
import datetime
import json
import sys
import io
import pickle
import socket
import json
import yaml
from urllib.parse import urlparse
from pathlib import Path
import geoip2.database
import requests
from netaddr import IPNetwork, IPAddress
import argparse

# Developed by David Dym @ easymetadata.com 
# v1 07/05/2020 -Updated for python3
# v2 11/25/2020
# 

#whois_cache = []
fqdn_cache = {}

dicLists = {}
#documents = []


def getFeedsFromYml():
    with open('lists.yml', 'r') as file:
        documents = yaml.full_load(file)
    return documents
    # for item, doc in documents.items():
    #     if "netset" in item:
    #         for itm in doc:
    #             print(itm['url'])
            #print(item, ":", doc)


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

def getGeoInfo(IP):
    result = []

    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            responseCity = reader.city(IP)

            if(responseCity.city.name):
                result.append(responseCity.city.name)
            else:
                result.append("\"\"")
            if(responseCity.country.name):
                result.append(responseCity.country.name)
            else:
                result.append("\"\"")
    except:
        result.append("\"\"")

    try:
        with geoip2.database.Reader('GeoLite2-ASN.mmdb') as reader:
            responseASN = reader.asn(IP)
            if(responseASN.autonomous_system_organization):
                result.append("\"" + responseASN.autonomous_system_organization.replace(","," ") + "\"")
            else:
                result.append("\"\"")
    except:
        result.append("\"\"")

    return ",".join(result)

def GetFireHoleLists(outFilename,strUrl,fList):   
    my_file = Path(outFilename)
    if not my_file.exists():
        print("Fetching firehole list: " + outFilename)
        r = requests.get(strUrl, allow_redirects=True)
        fireholeraw = r.content.decode()

        with open(outFilename,'w') as outFHfile:
            for i, line in enumerate(fireholeraw):
                outFHfile.write(line)
    else:
        #check age of file 
        today = datetime.datetime.today()
        modified_date = datetime.datetime.fromtimestamp(os.path.getmtime(my_file))
        duration = today - modified_date
        if(duration.total_seconds() > 86400):
            print("Feed '" + outFilename + "' older than 24 hours... refreshing.")
            os.remove(my_file)
            GetFireHoleLists(outFilename,strUrl,fList)

    with open(outFilename,'r') as inF:
        #fList.clear()
        tList = []
        for line in inF:
            if not line.startswith("#",0,1):
                tList.append(line.rstrip())

        dicLists[fList] = list(set(tList))

def CheckFireHoleList_cidr(ip,flist,strMessage):
    #https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python-2-x
    for ncidr in flist[35:]:
        try:
            if IPAddress(ip) in IPNetwork(ncidr.rstrip()): 
                return strMessage
        except:
            print(ncidr)
    return ""

def Checkcidr(ip, lst):
    print(ip)
#https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python-2-x
    for line in lst:
        try:
            if IPAddress(ip.rstrip()) in IPNetwork(line.rstrip()): 
                return True
        except:
            print("errorrrrr")
    return False

def ipProcess(ip,args):
    
    row = ip + ","
    row += getGeoInfo(ip)
    
    #this checks full cidr range. need to incorporate into all searches below...
    #fh = CheckFireHoleList_cidr(ip.rstrip(),firehole_list,"level 1")

    if args.FQDN:
        row += ", " + CheckFQDN(ip.rstrip())
    
    fhresult = ""

    for kLstName, vLstValues in dicLists.items():
        if ip in vLstValues:
                fhresult += kLstName + "|"
        # #now check cidr ranges
        # if "/" in vLstValues:
        #     try:
        #         lstCIDRonly = [x for x in vLstValues if '/' in x]
        #         for strCIDR in lstCIDRonly:
        #             if Checkcidr(ip,strCIDR):
        #                 if kLstName not in fhresult:
        #                     fhresult += fhresult + kLstName + "|"
        #     except:
        #         continue

    #If we have hits from feeds clean up the end
    if fhresult:
        row += "," + fhresult.rstrip("|")

    if fhresult and args.bHitsOnly:
        print (row)
    else:
        if not args.bHitsOnly:
            print (row)

def setupFeeds(documents):
    for item, doc in documents.items():
        #if "netset" in item:
        for itm in doc:
            a = urlparse(itm['url'])
            fname=(os.path.basename(a.path))
            GetFireHoleLists(fname,itm['url'],itm['name'])

def main():
    parser = argparse.ArgumentParser(description='A tool to gather information garding IPs')
    parser.add_argument("-f", "--file", dest='file', type=str, required=False, help="File with list of IPs one per line")
    parser.add_argument("-i", "--i", dest='ip', type=str, required=False, help="IPs to lookup")
    parser.add_argument("-n", "--HitsOnly", dest='bHitsOnly', required=False,action='store_true', help="Only show hits from threat feeds 'True'")
    parser.add_argument("-r", "--FQDN", dest='FQDN', required=False,action='store_true', help="Resolve FQDN. Provide 'True'")

    args = parser.parse_args()

    #GetFireHoleLists()
    loadFQDNcache()

    documents = getFeedsFromYml()

    setupFeeds(documents)

    print("IP, City, Country, ASN Org, FQDN, Indicators")

    if args.file:
        with open(args.file, "r") as f:
            for ip in f:
                ipProcess(ip.rstrip(),args)
    elif args.ip:
        ipProcess(args.ip.rstrip(),args)
    else:
        print("Provide an ip or file to process...")

    # save fqdn cache
    writeFQDNcache()

if True:
    main()