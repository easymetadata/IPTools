#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# 11/25/2020 Rewrite to make lists into separate yml. Add update to list based on age
# 06/15/2021 Implemened joblib for faster updating and processing. Cleaned up output with quoting. Refactored code.
# 07/31/2021 Implemented cidr enumeration for ip networks. IP's will now match against ip network netsets
# 02/12/2022 Updates and refactoring. Added xlsx output. Updated lists adding new feeds
# 06/07/2022 Added ASN matching to 'asnsets' such as bad asn lookups.
# 04/15/2023 Code refactoring / cleanup
# 08/22/2023 Heavy refactoring for performance. Added html browser output. Added VirusTotal lookup summary. Other fun stuff..
import argparse
import concurrent.futures
from datetime import datetime
from joblib import Parallel, delayed
import json
import multiprocessing
import os
import io
import pandas as pd
from pandas.io.excel import ExcelWriter
from pathlib import Path
import requests
import socket
import sys
import time
import warnings
import yaml
from tabulate import tabulate
from geoip2.database import Reader, geoip2
from netaddr import IPAddress, IPNetwork
from urllib.parse import urlparse
import webbrowser

_path = os.path.dirname(os.path.abspath(sys.argv[0]))
getFQDN = False
bHitsOnly = False
bSkipFeeds = False
update_interval = 46400
fqdn_cache = {}
threat_feeds = {}
dicListCIDRS = {}
asn_lists = {}
documents = {}
bCheckVT = False
VIRUSTOTAL_API_KEY = ""
VTsleepTime = 30

def getFeedsFromYml() -> dict:
    with open('lists.yml', 'r') as file:
        documents = yaml.full_load(file)
    return documents

def check_fqdn(ip):
    try:
        if ip in fqdn_cache:
            return fqdn_cache[ip]
        else:
                data = socket.gethostbyaddr(ip)
                fqdn_cache[ip] = data[0]
                return data[0]
    except:
       return ""

def getGeoInfo(IP):
    result = [] 

    try:
       # with geoip2.database.Reader('GeoLite2-City.mmdb') as readCity:
            responseCity = readCity.city(IP)
            result.append(f'{responseCity.city.name}')
            result.append(f'{responseCity.country.name}')
    except Exception as e: 
        print(f"[error] geo city: {e}")
        result.append("")

    try:
        #with geoip2.database.Reader('GeoLite2-ASN.mmdb') as readASN:
            responseASN = readASN.asn(IP)

            #check asn list too
            strASN = f'{responseASN.autonomous_system_number}' or ' '

            #check's against ASN lists
            strASN = check_asn(strASN)

            #append ASN with ASN lookup result
            result.append(strASN)

            #map ASN Org
            result.append(f'{responseASN.autonomous_system_organization.replace(",","_")}' or ' ')

    except Exception as e: 
        print(f"[error] geo: {e}")
        result.append(' ')
        result.append(' ')

    return ",".join(result)

#This works as a fallback when we don't find an ASN for an IP in the MaxM*nd ASN db
def get_org_info(ip_address):
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url)
        json_data = response.json()
        asn = json_data['asn']
        org = json_data['org']
        result = f"{asn},{org}"
        return result
    except Exception as e:
        print(f'[error] get_org_info:{e}')
        return ""
    finally:
        print('Used get_or_info')

def get_feeds(force_update, feed, update_interval):
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    try:
        str_url = urlparse(feed['url'])
        fname = (os.path.basename(str_url.path))
        fext = ''.join(Path(fname).suffixes)
        outFilename = Path('cache', feed['name'] + fext)

        if force_update or not outFilename.exists():
            r = requests.get(feed['url'], verify=False, allow_redirects=True)
            feed_list_raw = r.content.decode()
            with open(outFilename,'w', encoding='utf-8') as out_fh_file:
                out_fh_file.write(feed_list_raw)
        else:
            # Check age of file
            current_date = datetime.today()
            modified_date = datetime.fromtimestamp(os.path.getmtime(outFilename))
            duration = current_date - modified_date
            if duration.total_seconds() > update_interval:
                os.remove(outFilename)
                get_feeds(force_update, feed, update_interval)
    except Exception as e:
        print(f"Error [feed]: {e}")

def load_feeds() -> dict:
    """
    Load threat feed documents from the cache into memory.
    :param documents: A dictionary of documents containing cached threat feeds.\n    :return: A dictionary of cached threat feeds.
    """
    for item, doc in documents.items():
        if "threat_feeds" in item:
            for feed in doc:
                # preprocess url
                a = urlparse(feed['url'])
                fname = os.path.basename(a.path)
                fext = ''.join(Path(fname).suffixes)
                # read in threat feeds from cache
                fpath = Path('cache', feed['name'] + fext)
                with open(fpath, 'r', encoding='utf-8') as in_file:
                    t_list = []
                    for line in in_file:
                        if not line.startswith("#", 0, 1):
                            t_list.append(line.rstrip())
                threat_feeds[feed['name']] = list(set(t_list))
    return threat_feeds

def load_asn_feeds():
    try:
        for item, doc in documents.items():
            if "asnsets" not in item:  # item name without "asnsets" will be ignored
                continue
            for itm in doc:
                url_path = urlparse(itm['url']).path
                file_name = os.path.basename(url_path)
                file_ext = ''.join(Path(file_name).suffixes)
                file_path = Path('cache', f"{itm['name']}{file_ext}")
                with open(file_path, 'r', encoding='utf-8') as f_in:
                    lines = f_in.readlines()
                    t_list = [line.strip() for line in lines if not line.startswith('#', 0, 1)]
                asn_lists[itm['name']] = list(set(t_list))
    except Exception as e:
        print(f"Error [load_asn_feeds]: {e}")

def setup_feeds(check_update):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
            for item, doc in documents.items():
                if "threat_feeds" in item or "asnsets" in item:
                    #i_update_hrs = update_interval/60/60
                    for itm in doc:
                        executor.submit(get_feeds, check_update, itm, update_interval)
    except Exception as err:
        print(f"[error] setup_feeds: {err}")

def check_asn(asn: dict) -> str:
    try:
        for list_name, values in asn_lists.items():
            if asn in "".join(values):
                return f"{asn} [{list_name}]"
        return asn
    except Exception as error:
        print(f"Err [check_asn]: {error}")
        return ""

def vt_is_malicious_ip(ip_address):
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }

        time.sleep(VTsleepTime)

        response = requests.get(url, headers=headers)
        data = response.json()

        lDetects = ['malicious','suspicious']

        if response.status_code == 200:
            if 'data' in data:
                attributes = data['data']['attributes']
                attrVtRep = attributes['reputation']
                if 'last_analysis_stats' in attributes:
                    stats = []
                    for val in attributes['last_analysis_stats']:
                        if attributes['last_analysis_stats'][val] > 0:
                            stats.append(f"{val}:{attributes['last_analysis_stats'][val]}")
                    #if any(map(lambda v: v in lDetects, stats)):
                    return ";".join(stats) + f";rep:{attrVtRep}"
                else:
                    return ""  # No analysis data available
            else:
                return ""  # No data available for the given IP
        else:
            print(f"Error: {data['error']['message']}")
            return ""  # Error occurred while querying the API
    except Exception as err:
        print(err)
        return ""

def ipProcess(_ip):
    
    ip = _ip.rstrip()
    row = ip + ","
    try:
        row += getGeoInfo(ip)
        
        if getFQDN:
            row += "," + check_fqdn(ip)
        else:
            row += ","

        #Lookup from threat feeds.
        if bSkipFeeds:
            fhresult = ""
            bHitfound = False

            for kLstName, vLstValues in threat_feeds.items():
                if ip in vLstValues:
                    fhresult += f"{kLstName}|"
                    bHitfound = True

            #No IP hit yet - now let's search CIDR sub sets
            if not bHitfound:
                try:
                    for kLstName, vLstValues in dicListCIDRS.items():
                        for item in vLstValues:
                            if ip in IPNetwork(item):
                                fhresult += f"{kLstName} (cidr)|"
                                bHitfound = True
                except Exception as e:
                    print(f"[error] CIDR matching: {e}")
            #If we have hits from feeds clean up the end
            if fhresult:
                row += "," + fhresult.rstrip("|") +""
            else:
                row += ", "

        if bCheckVT:
            vtResults = vt_is_malicious_ip(ip)
            if vtResults:
                row += f", {vtResults}"

    except Exception as err:
        print(err)

    finally:
        return row.rstrip(",")

def _finditem(obj, key):
    if key in obj: return obj[key]
    for k, v in obj.items():
        if isinstance(v,dict):
            item = _finditem(v, key)
            if item is not None:
                return item

def _getListKeyVal(_documents, keyGroup, keyName):
    for item, doc in _documents.items():
        if keyGroup in item:
            for item2 in doc:
                if keyName in item2['name']:
                    return item2['value']
                
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A tool to gather information garding IPs')
    parser.add_argument("-f", "--file", dest='file', type=str, required=False, help="File with list of IPs one per line")
    parser.add_argument("-i", "--i", dest='ip', type=str, required=False, help="Lookup single IP")
    parser.add_argument("-n", "--HitsOnly", dest='bHitsOnly', required=False,action='store_true', help="Only show hits from threat feeds 'True'")
    parser.add_argument("-j", "--SkipFeeds", dest='bSkipFeeds', required=False,action='store_false', help="Skip threat feed matching")
    parser.add_argument("-r", "--FQDN", dest='FQDN', required=False,action='store_true', help="Resolve FQDN. Provide 'True'")
    parser.add_argument("-o", "--outfile", dest='outfile', required=False, help="Output file name [default CSV]")
    parser.add_argument("-x", "--xlsx", dest='xlsx', required=False, action='store_true', help="Output results to a file in xlsx")
    parser.add_argument("-s", "--skip_update", dest='skip_update', required=False,action='store_true', help="I'm in a hurry.. Skip downloading updated lists")
    parser.add_argument("-t", "--htmlOutput", dest='bhtmlOutput', required=False,action='store_true', help="Print output to html and open in browser")
    parser.add_argument("-l", "--vtLookup", dest='bvtLookup', required=False,action='store_true', help="VirusTotal scoring (requires VT api key)")
     
    args = parser.parse_args()

    getFQDN = args.FQDN
    bHitsOnly = args.bHitsOnly
    bSkipFeeds = args.bSkipFeeds
    bCheckVT = args.bvtLookup
    strRptDT = time.strftime("%Y%m%d_%H%M%S")
    
    #Add cache folder for feeds if doesn't exist
    if not os.path.exists("cache"):
        os.makedirs("cache")
    
    documents = getFeedsFromYml()

    if bSkipFeeds:
        print("Fetching new and updated feeds... [Update older than 24 hrs]")
        setup_feeds(args.skip_update)
        load_feeds()
        load_asn_feeds()
    
    #seup vtApiKey
    VIRUSTOTAL_API_KEY = _getListKeyVal(documents, "api_keys","VIRUSTOTAL_API_KEY")
    VTsleepTime = int(_getListKeyVal(documents, "api_keys","VTsleepTime"))

    #Generate a sub list of cidr ranges from master list to speed things up later.
    for key, val in threat_feeds.items():
        dicListCIDRS[key] = [item for (item) in val if '/' in item]
        
    if getFQDN:
        print("Note: Hostname lookups will increase processing time.")

    lstColumns = ["IP,City,Country,ASN,ASN Org,FQDN,Indicators,VT"]

    lstResults = []
    with geoip2.database.Reader('GeoLite2-City.mmdb') as readCity:
        with geoip2.database.Reader('GeoLite2-ASN.mmdb') as readASN:
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

    #Output results to console
    df = pd.read_csv(io.StringIO("\n".join(lstResults)))
    df.fillna("",inplace=True)

    if args.bhtmlOutput:
        #df = df.drop('City', axis=1)
        if not getFQDN:
            df = df.drop('FQDN', axis=1)
            ## open in browser
        with open("htmlresults.html", 'w', encoding='utf-8') as f:
            htmOut=df.to_html()
            print(htmOut, file=f)
        webbrowser.open_new_tab('htmlresults.html')
        #print(tabulate(df, tablefmt="pretty", showindex="never"))
    else:
        #print(df.to_string())
        print("\r\n" + "\r\n".join(lstResults).replace(',','    '))


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
