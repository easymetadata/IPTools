#!/usr/env python
# Developed by David Dym @ easymetadata.com 
# 07/05/2020 Rewrite for python3
# 11/25/2020 Rewrite to make lists into separate yml. Add update to list based on age
# 02/23/2021 Ignore ssl warnings
# 02/25/2021 Add -o export option
# 02/28/2021 Add api lookup for entries not found in M*xmind ASN db
import os
import time
import datetime
import sys
import io
import pickle
import socket
import pandas as pd
import json
import yaml
from urllib.parse import urlparse
from pathlib import Path
import geoip2.database
import requests
from urllib3.exceptions import InsecureRequestWarning
from netaddr import IPNetwork, IPAddress
import argparse

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

fqdn_cache = {}

dicLists = {}

lstResults = []

def getFeedsFromYml():
    with open('lists.yml', 'r') as file:
        documents = yaml.full_load(file)
    return documents

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
        try:
                result.append("\"%s\"" % responseASN.autonomous_system_number)
        except:
            result.append("\"\"")
        try:
                if(responseASN.autonomous_system_organization):
                    result.append("\"%s\"" % responseASN.autonomous_system_organization.replace(","," "))
                else:
                    result.append("\"\"")
        except:
                result.append("\"\"")
    except:
        try:
            result.append("\"[not found]\",\"%s\"" % GetOrgInfoFallback(IP) )
        except:
            result.append("\"[not found]\",\"\"")

    return ",".join(result)

#This works as a fallback when we don't find an ASN for an IP in the MaxM*nd ASN db
def GetOrgInfoFallback(strQuery): 
    strUrl = "http://ip-api.com/json/" + strQuery
    r = requests.get(strUrl)
    return r.json()['org']

def GetFireHoleLists(outFilename,strUrl,fList):   
    my_file = Path(outFilename)
    if not my_file.exists():
        print("Fetching firehole list: " + outFilename)
        r = requests.get(strUrl, verify=False, allow_redirects=True)
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

    if args.FQDN:
        row += ", " + CheckFQDN(ip.rstrip())
    
    fhresult = ""

    for kLstName, vLstValues in dicLists.items():
        if ip in vLstValues:
                fhresult += kLstName + "|"

    #If we have hits from feeds clean up the end
    if fhresult:
        row += "," + fhresult.rstrip("|")

    if fhresult and args.bHitsOnly:
        lstResults.append(row)
        #print (row)
    else:
        if not args.bHitsOnly:
            lstResults.append(row)
            #print (row)

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
    parser.add_argument("-o", "--outfile", dest='outfile', required=False, help="Output results to a file")

    args = parser.parse_args()

    loadFQDNcache()

    documents = getFeedsFromYml()

    setupFeeds(documents)
    print("\n")

    lstColumns = ["IP, City, Country, ASN, ASN Org, FQDN, Indicators"]
    #lstResults.append(lstColumns)
    #print("\",\"".join(lstColumns) + "\"")

    if args.file:
        with open(args.file, "r") as f:
            for ip in f:
                ipProcess(ip.rstrip(),args)
    elif args.ip:
        ipProcess(args.ip.rstrip(),args)
    else:
        print("Provide an ip or file to process...")

    #write output file
    if args.outfile:
        with open(args.outfile, 'w') as f:
            print("\n".join(lstColumns), file=f)
            print("\n".join(lstResults), file=f)
    else:
        print("\r\n".join(lstColumns))
        print("\r\n".join(lstResults))
    # save fqdn cache
    writeFQDNcache()

if True:
    main()
