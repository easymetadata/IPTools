#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# 11/25/2020 Rewrite to make lists into separate yml. Add update to list based on age
# 06/15/2021 Implemened joblib for faster updating and processing. Cleaned up output with quoting. Refactored code.
# 07/31/2021 Implemented cidr enumeration for ip networks. IP's will now match against ip network netsets
# 02/12/2022 Updates and refactoring. Added xlsx output. Updated lists adding new feeds
# 06/07/2022 Added ASN matching to 'asnsets' such as bad asn lookups.
import os
import io
import sys
import datetime
import multiprocessing
from joblib import Parallel, delayed
import json
import socket
from pandas.io.excel import ExcelWriter
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
update_interval = 46400
fqdn_cache = {}
dicLists = {}
dicListCIDRS = {}
dicASNLists = {}

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
        try:
            if(responseCity.city.name):
                result.append("%s" % responseCity.city.name)
            else:
                result.append("")
        except Exception as e: print(e)
        try:
            if(responseCity.country.name):
                result.append("%s" % responseCity.country.name)
            else:
                result.append("")
        except Exception as e: print(e)
    except Exception as e: print(e)

    try:
        with geoip2.database.Reader('GeoLite2-ASN.mmdb') as readASN:
            responseASN = readASN.asn(IP)
            try:
                #check asn list too
               strASN = str(responseASN.autonomous_system_number)
               #strTASN = CheckASN(strASN)
               #if strTASN:
               strASN = CheckASN(strASN)
               #result.append("%s" % responseASN.autonomous_system_number)
               result.append(strASN)
            except:
                result.append("")
            try:
                if(responseASN.autonomous_system_organization):
                    result.append("%s" % responseASN.autonomous_system_organization.replace(","," "))
                else:
                    result.append("")
            except:
               result.append("")
    #except Exception as e: print(e)
    except Exception as e:
        return ",".join(result)
    return ",".join(result)

#This works as a fallback when we don't find an ASN for an IP in the MaxM*nd ASN db
def GetOrgInfoFallback(strQuery): 
        strUrl = "http://ip-api.com/json/" + strQuery
        r = requests.get(strUrl)
        strR = ""+ r.json()['asn'] + ","+  r.json()['org'] + ""
        return strR

def GetFeeds(skip_update, itm): 
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    try:
        strUrl = urlparse(itm['url'])
        fname=(os.path.basename(strUrl.path))
        fext = ''.join(Path(fname).suffixes)
        outFilename= Path('cache',itm['name'] + fext)

        if not skip_update:
            if not outFilename.exists():
                r = requests.get(itm['url'], verify=False, allow_redirects=True)
                feedlistraw = r.content.decode()
                #print("DL new list: %s" % outFilename)
                with open(outFilename,'w', encoding='utf-8') as outFHfile:
                    for i, line in enumerate(feedlistraw):
                        outFHfile.write(line)
            else:
                #Check age of file 
                today = datetime.datetime.today()
                modified_date = datetime.datetime.fromtimestamp(os.path.getmtime(outFilename))
                duration = today - modified_date
                if(duration.total_seconds() > update_interval):
                    os.remove(outFilename)
                    GetFeeds(skip_update, itm)
    except Exception as e: print(e)

def getGeoLiteDBs():
    for item, doc in documents.items():
        if "threat_feeds" in item:
            url = urlparse(item['url'])
            outFilename = item['name'] + "." + item['suffix']
            r = requests.get(url, verify=False, allow_redirects=True)
            #text = r.decode('utf-8') # a `str`; this step can't be used if data is binary
            with open(outFilename,'wb') as outFHfile:
                    outFHfile.write(r)

def LoadFeeds(documents):
    for item, doc in documents.items():
        if "threat_feeds" in item:
            for itm in doc:
                a = urlparse(itm['url'])
                fname=(os.path.basename(a.path))
                fext = ''.join(Path(fname).suffixes)
                fpath=Path('cache',itm['name'] + fext)
                with open(fpath,'r', encoding='utf-8') as inF:
                    tList = []
                    for line in inF:
                        if not line.startswith("#",0,1):
                            tList.append(line.rstrip())
                dicLists[itm['name']] = list(set(tList))

def LoadASNFeeds(documents):
    for item, doc in documents.items():
        if "asnsets" in item:
            for itm in doc:
                a = urlparse(itm['url'])
                fname=(os.path.basename(a.path))
                fext = ''.join(Path(fname).suffixes)
                fpath=Path('cache',itm['name'] + fext)
                with open(fpath,'r', encoding='utf-8') as inF:
                    tList = []
                    for line in inF:
                        #if not line.startswith("#",0,1):
                        tList.append(line.strip())
                dicASNLists[itm['name']] = list(set(tList))

def setupFeeds(check_update,documents):
    for item, doc in documents.items():
        if "threat_feeds" in item or "asnsets" in item:
            iUpdateHrs = update_interval/60/60
            Parallel(n_jobs=multiprocessing.cpu_count(),prefer='threads')(delayed(GetFeeds)(check_update,itm) for itm in doc)

def CheckASN(sASN):
    try:
        for kLstName, vLstValues in dicASNLists.items():
            #print("|" + vLstValues + "|")
            if sASN in "".join(vLstValues):
                #print(vLstValues)
                return sASN + " [" + kLstName + "]"
        return sASN
    except Exception as err:
        print(err)

#need to return row/rows here then add after exiting the thread!
def ipProcess(_ip):

    try:
        ip = _ip.rstrip()

        row = "" + ip + ","
        row += getGeoInfo(ip)

        if getFQDN:
            row += "," + CheckFQDN(ip.rstrip()) + ""
        else:
            row += ","

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
                for kLstName, vLstValues in dicListCIDRS.items():
                    for item in vLstValues:
                        if ip in IPNetwork(item):
                            fhresult += kLstName + " (cidr)|"
            
            #If we have hits from feeds clean up the end
            if fhresult:
                row += "," + fhresult.rstrip("|") +""

            if bHitsOnly and not fhresult:
                return ""
    #except Exception as e: print(e)
    finally:
        return row.rstrip(",")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A tool to gather information garding IPs')
    parser.add_argument("-f", "--file", dest='file', type=str, required=False, help="File with list of IPs one per line")
    parser.add_argument("-i", "--i", dest='ip', type=str, required=False, help="Lookup single IP")
    parser.add_argument("-n", "--HitsOnly", dest='bHitsOnly', required=False,action='store_true', help="Only show hits from threat feeds 'True'")
    parser.add_argument("-j", "--SkipFeeds", dest='bSkipFeeds', required=False,action='store_false', help="Skip threat feed matching")
    parser.add_argument("-r", "--FQDN", dest='FQDN', required=False,action='store_true', help="Resolve FQDN. Provide 'True'")
    parser.add_argument("-o", "--outfile", dest='outfile', required=False, help="Output file name [default CSV]")
    parser.add_argument("-x", "--xlsx", dest='xlsx', required=False, action='store_true', help="Output results to a file in xlsx")
    parser.add_argument("-s", "--skip_update", dest='skip_update', required=False,action='store_true', help="I'm in a hurry.. Skip downloading updated lists.")
    
    args = parser.parse_args()

    getFQDN = args.FQDN
    bHitsOnly = args.bHitsOnly
    bSkipFeeds = args.bSkipFeeds
    
    #Add cache folder for feeds if doesn't exist
    if not os.path.exists("cache"):
        os.makedirs("cache")
    
    documents = getFeedsFromYml()

    if bSkipFeeds:
        print("Fetching new and updated feeds... [Update older than 24 hrs]")
        setupFeeds(args.skip_update,documents)
        LoadFeeds(documents)
        LoadASNFeeds(documents)

    #Generate a sub list of cidr ranges from master list to speed things up later.
    for key, val in dicLists.items():
        dicListCIDRS[key] = [item for (item) in val if '/' in item]
        
    if getFQDN:
        print("Note: Hostname lookups will increase processing time.")

    lstColumns = ["IP,City,Country,ASN,ASN Org,FQDN,Indicators"]

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

    lstResults.insert(0,"\r\n".join(lstColumns))

    #Output results
    print("\r\n" + "\r\n".join(lstResults))

    #Write results to file
    if args.outfile:
        if not args.xlsx:
            with open(args.outfile, 'w', encoding='utf-8') as f:
                print("\n".join(lstResults), file=f)
            print("Results written to %s" % args.outfile)
    if args.xlsx:
        df = pd.read_csv(io.StringIO("\n".join(lstResults)))
        writer = pd.ExcelWriter(args.outfile.replace('.csv','') + '.xlsx', engine='xlsxwriter')
        df.to_excel(writer, sheet_name='results', index=False, header=True)
        writer.save()

print ("\n Lookups complete.")
