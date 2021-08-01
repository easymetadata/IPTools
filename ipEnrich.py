#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# 11/25/2020 Rewrite to make lists into separate yml. Add update to list based on age
# 06/15/2021 Implemened joblib for faster updating and processing. Cleaned up output with quoting. Refactored code.
# 07/31/2021 Implemented cidr enumeration for ip networks. IP's will now match against ip network netsets
import os
import sys
import datetime
import multiprocessing
from joblib import Parallel, delayed
import json
import socket
import pandas as pd
import yaml
from urllib.parse import urlparse
from pathlib import Path
import geoip2.database
import requests
from netaddr import IPNetwork, IPAddress
import argparse
import warnings

_path = os.path.dirname(os.path.abspath(sys.argv[0]))
getFQDN = False
bHitsOnly = False
bSkipFeeds = False
update_interval = 86400
fqdn_cache = {}
dicLists = {}
dicListCIDRS = {}
dictASNs = {}

def getFeedsFromYml():
    with open('lists.yml', 'r') as file:
        documents = yaml.full_load(file)
    return documents

def CheckFQDN(ip):
    hostdns = ""
    try:
        if ip in fqdn_cache:
            return fqdn_cache.get(ip)
        else:
            data = socket.gethostbyaddr(ip)
            if repr(data[0]):
                hostdns = "{}".format(repr(data[0]).replace('\'',''))

                 #update cache
                fqdn_cache[ip] = hostdns
    except:
        hostdns = ""
    return hostdns

def getGeoInfo(IP):
    result = [] 

    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as readCity:
            responseCity = readCity.city(IP)

        if(responseCity.city.name):
            result.append("\"%s\"" % responseCity.city.name)
        else:
            result.append("\"\"")
        if(responseCity.country.name):
            result.append("\"%s\"" % responseCity.country.name)
        else:
            result.append("\"\"")
    except Exception as e: print(e)

    try:
        with geoip2.database.Reader('GeoLite2-ASN.mmdb') as readASN:
            responseASN = readASN.asn(IP)
        try:
                #result.append("\"%s\"" % responseASN.autonomous_system_number)
                result.append("\"%s\"" % responseASN.autonomous_system_number)
        except:
            result.append("\"\"")
        try:
                if(responseASN.autonomous_system_organization):
                    result.append("\"%s\"" % responseASN.autonomous_system_organization.replace(","," "))
                else:
                    result.append("\"\"")
        except Exception as e: print(e)
        #except:
        #        result.append("\"\"")
    except:
        try:
            result.append("\"[not found]\",\"%s\"" % GetOrgInfoFallback(IP) )
            #result.append("(MaxMind failed)" )
        except:
            result.append("\"[not found]\",\"\"")

    return ",".join(result)

#This works as a fallback when we don't find an ASN for an IP in the MaxM*nd ASN db
def GetOrgInfoFallback(strQuery): 
    try:
        strUrl = "http://ip-api.com/json/" + strQuery
        r = requests.get(strUrl)
        return r.json()['org']
    except Exception as e: print(e)
    return ""

def GetFireHoleLists(skip_update, itm): 
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    try:
        strUrl = urlparse(itm['url'])
        outFilename=(os.path.basename(strUrl.path))
        my_file = Path(outFilename)

        if not skip_update:
            if not my_file.exists():
                r = requests.get(itm['url'], verify=False, allow_redirects=True)
                fireholeraw = r.content.decode()
                print("DL new list: %s" % outFilename)
                with open(outFilename,'w', encoding='utf-8') as outFHfile:
                    for i, line in enumerate(fireholeraw):
                        outFHfile.write(line)
            else:
                #Check age of file 
                today = datetime.datetime.today()
                modified_date = datetime.datetime.fromtimestamp(os.path.getmtime(my_file))
                duration = today - modified_date
                if(duration.total_seconds() > update_interval):
                    os.remove(my_file)
                    GetFireHoleLists(skip_update, itm)
    except Exception as e: print(e)

def LoadFeeds(documents):
    for item, doc in documents.items():
        if "netset" in item or "ipset" in item:
            for itm in doc:
                a = urlparse(itm['url'])
                fname=(os.path.basename(a.path))
                with open(fname,'r', encoding='utf-8') as inF:
                    tList = []
                    for line in inF:
                        if not line.startswith("#",0,1):
                            tList.append(line.rstrip())
                dicLists[itm['name']] = list(set(tList))

def setupFeeds(check_update,documents):
    for item, doc in documents.items():
        if "netset" in item or "ipset" in item:
            iUpdateHrs = update_interval/60/60
            Parallel(n_jobs=multiprocessing.cpu_count(),prefer='threads')(delayed(GetFireHoleLists)(check_update,itm) for itm in doc)

def CheckASN(sASN):
    for kLstName, vLstValues in dicLists.items():
        if sASN in vLstValues:
                return kLstName + "|"
    return ""

#need to return row/rows here then add after exiting the thread!
def ipProcess(_ip):

    try:
        ip = _ip.rstrip()

        row = "\"" + ip + "\","
        row += getGeoInfo(ip)

        if getFQDN:
            row += ",\"" + CheckFQDN(ip.rstrip()) + "\""
        else:
            row += ",\"\""

        #Lookup from threat feeds.
        if bSkipFeeds:
            fhresult = ""
            bHitfound = False

            for kLstName, vLstValues in dicLists.items():
                if ip in vLstValues:
                    fhresult += kLstName + "|"
                    bHitfound = True

            #No IP hit yet - now let's search CIDR sub sets
            if not bHitfound:
                try:
                    for kLstName, vLstValues in dicListCIDRS.items():
                        for item in vLstValues:
                            if ip in IPNetwork(item):
                                fhresult += kLstName + " (cidr)|"
                except Exception as e:
                    print(e)
            
            #If we have hits from feeds clean up the end
            if fhresult:
                row += ",\"" + fhresult.rstrip("|") +"\""

            if bHitsOnly and not fhresult:
                return ""

    except Exception as e: print(e)

    return row

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A tool to gather information garding IPs')
    parser.add_argument("-f", "--file", dest='file', type=str, required=False, help="File with list of IPs one per line")
    parser.add_argument("-i", "--i", dest='ip', type=str, required=False, help="Lookup single IP")
    parser.add_argument("-n", "--HitsOnly", dest='bHitsOnly', required=False,action='store_true', help="Only show hits from threat feeds 'True'")
    parser.add_argument("-j", "--SkipFeeds", dest='bSkipFeeds', required=False,action='store_false', help="Skip threat feed matching")
    parser.add_argument("-r", "--FQDN", dest='FQDN', required=False,action='store_true', help="Resolve FQDN. Provide 'True'")
    parser.add_argument("-o", "--outfile", dest='outfile', required=False, help="Output results to a file in CSV")
    parser.add_argument("-s", "--skip_update", dest='skip_update', required=False,action='store_true', help="I'm in a hurry.. Skip downloading updated lists.")
    
    args = parser.parse_args()

    getFQDN = args.FQDN
    bHitsOnly = args.bHitsOnly
    bSkipFeeds = args.bSkipFeeds

    documents = getFeedsFromYml()

    if bSkipFeeds:
        print("Fetching new and updated feeds... [Update older than 24 hrs]")
        setupFeeds(args.skip_update,documents)
        LoadFeeds(documents)

    #Generate a sub list of cidr ranges from master list to speed things up later.
    for key, val in dicLists.items():
        dicListCIDRS[key] = [item for (item) in val if '/' in item]
        
    if getFQDN:
        print("Note: Hostname lookups will increase processing time.")

    lstColumns = ["IP, City, Country, ASN, ASN Org, FQDN, Indicators"]

    lstResults = []

    if args.file:
        with open(args.file, "r", encoding='utf-8') as f:
            lstResults = Parallel(n_jobs=multiprocessing.cpu_count(),prefer='threads')(delayed(ipProcess)(ip) for ip in f)
    elif args.ip:
        lstResults.append(ipProcess(args.ip.rstrip()))
    else:
        print("Provide an ip or file to process...")

    #Remove skipped lines that didn't have threat feed hits
    if(bHitsOnly):
        lstResults = [i for i in lstResults if i]

    #Output results
    print ("\r\n")
    print("\r\n".join(lstColumns))
    print("\r\n".join(lstResults))
    
    #Write results to file
    if args.outfile:
        with open(args.outfile, 'w', encoding='utf-8') as f:
            print("\n".join(lstColumns), file=f)
            print("\n".join(lstResults), file=f)
        print("Results written to %s" % args.outfile)

print ("\n Lookups complete.")
