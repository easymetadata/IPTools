#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# 08/22/2023 Heavy refactoring for performance. Added html browser output. Added VirusTotal lookup summary. Other fun stuff..
# 10/21/2023 Refactor output for html, browser and xlsx for cross platform support
# 11/11/2023 Refactor export options and behavior. Change html output to unique filename. Change whois api fallback in lists.yml. Add initial sqlitedb
# 11/19/2023 Bugfix for strtime format error on windows systems
import argparse
import concurrent.futures
from datetime import datetime
from joblib import Parallel, delayed
import json
import multiprocessing
import os
import io
import pandas as pd
from tabulate import tabulate
from pathlib import Path
import requests
import socket
import sys
import time
import warnings
import yaml
from geoip2.database import Reader, geoip2
import geoip2.errors
from netaddr import IPAddress, IPNetwork
from ipwhois import IPWhois
import sqlite3
from urllib.parse import urlparse
import webbrowser
import logging

#import sqlite3

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

def getGeoInfo(ip_address):
    result = [] 

    try:
       # with geoip2.database.Reader('GeoLite2-City.mmdb') as readCity:
            responseCity = readCity.city(f"{ip_address}")
            #result.append("%s" % responseCity.city.name or "")
            result.append(f'{responseCity.country.name}')
    except Exception as e: 
        print(f"[error] geo city: {e}")
        logging.exception(f"[error] geo city: {e}")
        result.append("")

    try:
        #with geoip2.database.Reader('GeoLite2-ASN.mmdb') as readASN:
            responseASN = readASN.asn(ip_address)

            #check asn list too
            strASN = f'{responseASN.autonomous_system_number}' or ' '

            #check's against ASN lists
            strASN = check_asn(f"{strASN}")

            #append ASN with ASN lookup result
            result.append(f"{strASN}")

            #map ASN Org
            result.append(f'{responseASN.autonomous_system_organization.replace(",","_")}' or ' ')

    except geoip2.errors.AddressNotFoundError as e: 
        print(f"geo: {ip_address} {e} - api fallback]")
        #logging.exception(f"geo: {ip_address} {e} not found - fallback to api lookup]")
        for itm in get_org_info(ip_address):
            result.append(f"{itm}".replace(",","_"))
        #result.append(' ')
        #result.append(' ')
    except Exception as e:
         print(f"[error] geo: {e}")
    #     logging.exception(f"[error] geo: {e}")

    return ",".join(result)

#This works as a fallback when we don't find an ASN for an IP in the MaxM*nd ASN db
def get_org_info(ip_address):
    result = []
    try:
        url = f"http://ipwho.is/{ip_address}"
        response = requests.get(url)
        data = json.loads(response.content)
        connection_info = data.get("connection")
        if connection_info:
            sAsn = connection_info.get("asn")
            if sAsn:
                sAsn = check_asn(f'{sAsn}')
            result.append(sAsn)
            sOrg = connection_info.get("org")
            result.append(sOrg)
        return result
    except Exception as e:
        print(f'[error] get_org_info:{e}')
        logging.exception(f'[error] get_org_info:{e}')

    result.append("")
    result.append("")
    return result

    return result

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
        print(f"Error [get_feeds]: {e}")
        logging.exception(f"Error [get_feeds]: {e}")

def load_feeds() -> dict:
    """
    Load threat feed documents from the cache into memory.
    :param documents: A dictionary of documents containing cached threat feeds.\n    :return: A dictionary of cached threat feeds.
    """
    try:
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
    except Exception as e:
        print(f"Error [load_feeds]: {e}")
        logging.exception(f"Error [load_feeds]: {e}")

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
        logging.exception(f"Error [load_asn_feeds]: {e}")

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
        logging.exception(f"[error] setup_feeds: {err}")

def check_asn(asn):
    try:
        for list_name, values in asn_lists.items():
            if asn in "".join(values):
            #if asn in values:
                return f"{asn} [{list_name}]"
    except Exception as error:
        print(f"Err [check_asn]: {error}")
        logging.exception(f"Err [check_asn]: {error}")
    return f"{asn}"

def vt_is_malicious_ip(ip_address):
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }

        time.sleep(VTsleepTime)

        response = requests.get(url, headers=headers)
        data = response.json()

        #lDetects = ['malicious','suspicious']

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
                    return ";".join(stats) + f",{attrVtRep}"
                else:
                    return ""  # No analysis data available
            else:
                return ""  # No data available for the given IP
        else:
            print(f"Error: {data['error']['message']}")
            return ""  # Error occurred while querying the API
    except Exception as err:
        logging.exception(err)
        print(err)
        return ""

def ipProcess(ip):
    
    #ip = ip.rstrip()
    row = f"{ip},"
    try:
        row += getGeoInfo(ip)
        
        if getFQDN:
            row += f",{check_fqdn(ip)}"
        else:
            row += ","

        #Lookup from threat feeds.
        if bSkipFeeds:
            fhresult = ""
            bHitfound = False

            for kLstName, vLstValues in threat_feeds.items():
                if ip in vLstValues:
                    fhresult += f"{kLstName} | "
                    bHitfound = True

            #No IP hit yet - now let's search the dictionary of calculated CIDR sub sets
            if not bHitfound:
                try:
                    for kLstName, vLstValues in dicListCIDRS.items():
                        for item in vLstValues:
                            if ip in IPNetwork(item):
                                fhresult += f"{kLstName} (cidr) | "
                                bHitfound = True
                except Exception as e:
                    logging.debug(f"[error] CIDR matching {ip}: {e}")
            #If we have hits from feeds clean up the end
            if fhresult:
                row += "," + fhresult.rstrip(" | ") +""
            else:
                row += ","

        if bCheckVT:
            vtResults = vt_is_malicious_ip(ip)
            if vtResults:
                row += f", {vtResults}"

    except Exception as err:
        logging.exception(err)
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
    parser.add_argument("-c", "--csv", dest='csv', required=False, action='store_true',help="Output results to CSV")
    parser.add_argument("-x", "--xlsx", dest='xlsx', required=False, action='store_true', help="Output results to a file in xlsx")
    parser.add_argument("-d", "--sqlite", dest='sqlite', required=False, action='store_true', help="Output results to a sqlite db")
    parser.add_argument("-s", "--skip_update", dest='skip_update', required=False,action='store_true', help="I'm in a hurry.. Skip downloading updated lists")
    parser.add_argument("-t", "--htmlOutput", dest='bhtmlOutput', required=False,action='store_true', help="Output to html in a browser")
    parser.add_argument("-l", "--vtLookup", dest='bvtLookup', required=False,action='store_true', help="VirusTotal scoring")
    parser.add_argument("-b", "--json", dest='json', required=False,action='store_true', help="Output results to file in json")

    args = parser.parse_args()

    getFQDN = args.FQDN
    bHitsOnly = args.bHitsOnly
    bSkipFeeds = args.bSkipFeeds
    bCheckVT = args.bvtLookup
    strRptDT = int(time.strftime('%Y%m%d%H%M%S'))
    
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
    print("Populating list of items from feeds with cidr ranges..")
    for key, val in threat_feeds.items():
        dicListCIDRS[key] = [item for (item) in val if '/' in item]
        
    if getFQDN:
        print("Note: Reverse lookups will increase processing time.")

    lstColumns = ["IP,Country,ASN,ASN Org,FQDN,Indicators,VT,VT Rep"]

    lstResults = []
    with geoip2.database.Reader('GeoLite2-City.mmdb') as readCity:
        with geoip2.database.Reader('GeoLite2-ASN.mmdb') as readASN:
            if args.file:
                with open(args.file, "r", encoding='utf-8') as file:
                    #Remove trailing \n
                    lstIps = [line.rstrip() for line in file.readlines()]
                    #Loop through the list of IP's using a thread process
                    lstResults = Parallel(n_jobs=multiprocessing.cpu_count(),prefer='threads')(delayed(ipProcess)(ip) for ip in lstIps)
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

    #Remove columns without values
    df.dropna(axis=1, how='all', inplace=True)

    #Fills empty values to avoid NaN
    df = df.where(pd.notna(df), '')

    # create a Styler
    df_styled = df.style.set_properties(
        **{'font-size': '10pt','background-color': '#edeeef','border-color': 'black','border-style' :'solid' ,'border-width': '0px','border-collapse':'collapse'}
    ).hide(axis="index")
    
    #Setup output filename
    current_directory = os.getcwd()
    #tmpStrTime = time.strftime('%Y%m%d%H%M%S')
    tmpOutFileName = current_directory + f"/results{strRptDT}"
    
    #print final results to console if anything other than HTML output
    if not args.bhtmlOutput:
        print(tabulate(df,df.columns, tablefmt="simple",showindex=False))
        print("")

    #Output to file options
    if args.bhtmlOutput:
        #If output to html is selected write to html file and open a new browser window 
        tmpOutHtml = tmpOutFileName + '.html'   
        with open(tmpOutHtml, 'w', encoding='utf-8') as f:
            print(df_styled.to_html(), file=f)
        webbrowser.open_new('file://' + tmpOutHtml)
        print(f"Results written to {tmpOutHtml}")
    if args.csv:
        df.to_csv(f"{tmpOutFileName}.csv", index=False,header=True)
        print(f"Results written to {tmpOutFileName}.csv")
    if args.xlsx:
        df_styled.to_excel(f"{tmpOutFileName}.xlsx", sheet_name='results', index=False, header=True)
        print(f"Results written to {tmpOutFileName}.xlsx")
    if args.json:
        df.to_json(f"{tmpOutFileName}.json", index=False)
        print(f"Results written to {tmpOutFileName}.json")
    if args.sqlite:
        #save results to sqlitedb
        conn = sqlite3.connect(f"{tmpOutFileName}.sqlitedb")
        df.to_sql('lookups', conn, if_exists='append', index=False)
        print(f"Results written to {tmpOutFileName}.sqlitedb")

print ("\n Lookups complete.")
