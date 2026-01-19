#!/usr/bin/python
# Developed by David Dym @ easymetadata.com 
# Version 3.0
# Date: 2025-08-12
# This script is a tool to gather information regarding IPs, including geolocation, ASN, threat feed matching, and VirusTotal lookups.

import argparse
from datetime import datetime
import json
import multiprocessing
import os
import pandas as pd
from tabulate import tabulate
from pathlib import Path
import requests
import socket
import sys
import time
import warnings
import yaml
from geoip2.database import geoip2
import geoip2.errors
from netaddr import IPNetwork
import sqlite3
from urllib.parse import urlparse
import webbrowser
import logging

# import sqlite3

# Import functions from separate modules
from geo_api import get_geo_infoAPI
from virustotal_api import vt_is_malicious_ip
from ip_utils import is_private_ip, get_private_ip_reason

_path = os.path.dirname(os.path.abspath(sys.argv[0]))
gethost = False
gethostAPI = False
bHitsOnly = False
bSkipFeeds = False
update_interval = 46400
host_cache = {}
threat_feeds = {}
dicListCIDRS = {}
asn_lists = {}
documents = {}
bCheckVT = False
VIRUSTOTAL_API_KEY = ""
VTsleepTime = 31  # seconds to wait between requests to VirusTotal API
bAllowPrivate = False  # Whether to allow processing of private IPs

class Result:
    def __init__(self, ip='', country='', city='', asn='', asn_org='', isp = '', host='', indicators=None, vt=None, vt_rep=None, is_proxy='', notes=None):
        self.ip = ip
        self.country = country
        self.city = city
        self.asn = asn
        self.asn_org = asn_org
        self.isp = isp
        self.host = host
        self.indicators = indicators
        self.vt = vt
        self.vt_rep = vt_rep
        self.is_proxy = is_proxy
        self.notes = notes  # Placeholder for any additional notes or comments


def get_feeds_from_yml() -> dict:
    with open('lists.yml', 'r') as file:
        documents = yaml.full_load(file)
    return documents

## Lookup hostname using local dns lookup
def check_host(ip):
    try:
        if ip in host_cache:
            return host_cache[ip]
        else:
            data = socket.gethostbyaddr(ip)
            print(data)
            host_cache[ip] = data[0]
            return data[0]
    except Exception as e:
        return ""




def getGeoInfo(ip_address, readCity, readASN):
    result = Result(ip=ip_address, country='', city='', asn='', asn_org='', isp='', host='', indicators='', vt='', vt_rep='', is_proxy='', notes='')

    try:
        responseCity = readCity.city(ip_address)
        if responseCity.city.name is not None:
            result.city = responseCity.city.name
        if responseCity.country.name is not None:
            result.country = responseCity.country.name

    # try:
        responseASN = readASN.asn(ip_address)
        result.asn = f'{responseASN.autonomous_system_number}'
        result.asn_org = f'{responseASN.autonomous_system_organization.replace(",", "_")}'
        #result.isp = f'{responseASN.isp}'

    except geoip2.errors.AddressNotFoundError:
        logging.warning(f"ASN information not found for IP: {ip_address}")
    except Exception as e:
        logging.exception(f"geo: {ip_address} {e} not found - fallback to api lookup]")

    if result.asn != "" and result.asn_org != "":
        result.notes = check_asn_rep(f'{result.asn}')

    return result




def get_feeds(force_update, feed, update_interval):
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    try:
        str_url = urlparse(feed['url'])
        fname = (os.path.basename(str_url.path))
        fext = ''.join(Path(fname).suffixes)
        path = Path('cache', feed['name'] + fext)
        outFilename = path

        if force_update or not outFilename.exists():
            r = requests.get(feed['url'], verify=False, allow_redirects=True)
            if r.status_code == 200:
                feed_list_raw = r.content.decode()
                with open(outFilename, 'w', encoding='utf-8') as out_fh_file:
                    out_fh_file.write(feed_list_raw)
            else:
                print(f"Error: {r.status_code} - {r.text}")
                return
        else:
            # Check age of file
            current_date = datetime.today()
            modified_date = datetime.fromtimestamp(os.path.getmtime(outFilename))
            duration = current_date - modified_date
            if duration.total_seconds() > update_interval:
                os.remove(outFilename)
                get_feeds(force_update, feed, update_interval)
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error while fetching {feed['url']}: {e}")
        return
    except requests.exceptions.RequestException as e:
        # Catch any other requests-related exceptions
        print(f"Error fetching {feed['url']}: {e}")
        return


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


def get_database_paths():
    """Get the proper paths for GeoIP database files"""
    base_path = os.path.dirname(os.path.abspath(__file__))
    city_db = os.path.join(base_path, 'GeoLite2-City.mmdb')
    asn_db = os.path.join(base_path, 'GeoLite2-ASN.mmdb')
    return city_db, asn_db

def validate_database_files():
    """Validate that required database files exist"""
    city_db, asn_db = get_database_paths()
    missing_files = []
    
    if not os.path.exists(city_db):
        missing_files.append('GeoLite2-City.mmdb')
    if not os.path.exists(asn_db):
        missing_files.append('GeoLite2-ASN.mmdb')
    
    if missing_files:
        print(f"Warning: Missing required database files: {', '.join(missing_files)}")
        print("Please ensure these files are in the same directory as the script.")
        return False
    return True

def check_threat_feeds(ip, threat_feeds_data, dicListCIDRS_data, skip_feeds):
    """
    Check if an IP appears in threat feeds and CIDR ranges.
    
    Args:
        ip: IP address to check
        threat_feeds_data: Dictionary of threat feed data
        dicListCIDRS_data: Dictionary of CIDR range data
        skip_feeds: Boolean flag to skip feed checking
        
    Returns:
        tuple: (indicators_string, is_proxy_flag)
    """
    if skip_feeds:
        return "", None
        
    fhresult = ""
    bHitfound = False

    # Check direct IP matches
    for kLstName, vLstValues in threat_feeds_data.items():
        if ip in vLstValues:
            fhresult += f"{kLstName} | "
            bHitfound = True

    # Check CIDR range matches if no direct hit
    if not bHitfound:
        try:
            for kLstName, vLstValues in dicListCIDRS_data.items():
                for item in vLstValues:
                    if ip in IPNetwork(item):
                        fhresult += f"{kLstName} (cidr) | "
                        bHitfound = True
        except Exception as e:
            logging.debug(f"[error] CIDR matching {ip}: {e}")

    # Clean up and determine proxy status
    indicators = fhresult.rstrip(" | ") if fhresult else ""
    is_proxy = "proxy" if ("proxy" in indicators or "proxie" in indicators) else None
    
    return indicators, is_proxy

def update_result_with_threat_data(result, indicators, is_proxy):
    """
    Update a Result object with threat feed information.
    
    Args:
        result: Result object to update
        indicators: Threat indicators string
        is_proxy: Proxy flag
    """
    if indicators:
        result.indicators = indicators
        if is_proxy:
            result.is_proxy = is_proxy

def process_ip_chunk(args_tuple):
    """Process a chunk of IPs and return results"""
    ip_chunk, threat_feeds_data, dicListCIDRS_data, skip_feeds = args_tuple
    
    # Debug: Show what data we received
    #print(f"Worker process received {len(threat_feeds_data)} threat feeds and {len(dicListCIDRS_data)} CIDR lists")
    
    results = []
    for ip in ip_chunk:
        try:
            result = ipProcess(ip, None, None)
            
            # Check threat feeds locally since we have the data
            # Note: skip_feeds True means skip feeds, False means check feeds
            if not skip_feeds:
                indicators, is_proxy = check_threat_feeds(ip, threat_feeds_data, dicListCIDRS_data, skip_feeds)
                update_result_with_threat_data(result, indicators, is_proxy)

            results.append(result)
        except Exception as e:
            logging.error(f"Error processing IP {ip}: {e}")
            # Create a default result for failed IPs
            failed_result = Result(ip=ip)
            failed_result.notes = f"Processing failed: {e}"
            results.append(failed_result)
    return results

def setup_feeds(check_update):
    try:
        # Use multiprocessing.Pool for parallel feed processing
        with multiprocessing.Pool(processes=min(multiprocessing.cpu_count(), 8)) as pool:
            feed_tasks = []
            for item, doc in documents.items():
                if "threat_feeds" in item or "asnsets" in item:
                    for itm in doc:
                        feed_tasks.append((check_update, itm, update_interval))
            
            # Process all feeds in parallel
            if feed_tasks:
                pool.starmap(get_feeds, feed_tasks)
    except Exception as err:
        print(f"[error] setup_feeds: {err}")
        logging.exception(f"[error] setup_feeds: {err}")

# This function checks the ASN against an ASN rep list
def check_asn_rep(asn):
    try:
        for list_name, values in asn_lists.items():
            if asn in "".join(values):
                return f"ASN Rep: {list_name}"
    except Exception as error:
        print(f"Err [check_asn]: {error}")
        logging.exception(f"Err [check_asn]: {error}")
    return ""



# This is the main mapping function
def ipProcess(ip, readCity, readASN):
    # Initialize the result dictionary
    result_dict = Result(ip=ip)
    
    # Check if IP is private - skip processing if it is (unless explicitly allowed)
    if not bAllowPrivate and is_private_ip(ip):
        reason = get_private_ip_reason(ip)
        result_dict.notes = f"Skipped: {reason}"
        logging.info(f"Skipping private IP {ip}: {reason}")
        return result_dict
    
    # For multiprocessing, create database readers if None is passed
    local_readCity = readCity
    local_readASN = readASN
    
    if readCity is None or readASN is None:
        try:
            city_db, asn_db = get_database_paths()
            local_readCity = geoip2.database.Reader(city_db)
            local_readASN = geoip2.database.Reader(asn_db)
        except Exception as e:
            logging.error(f"Failed to open database files: {e}")
            return result_dict
    
    try:
        #if not gethost:
        result_dict = getGeoInfo(ip, local_readCity, local_readASN)

        # Get host from whois
        if gethost:
            result_dict.host = check_host(ip)

        # Get host from API
        if gethostAPI:
            result_dict = get_geo_infoAPI(ip, result_dict)

        # Note: This threat feed checking is now done in worker processes for multiprocessing
        # This code is only used for single IP processing or fallback
        if not bSkipFeeds:
            indicators, is_proxy = check_threat_feeds(ip, threat_feeds, dicListCIDRS, bSkipFeeds)
            update_result_with_threat_data(result_dict, indicators, is_proxy)

    except Exception as err:
        logging.exception(err)
        print(err)
    finally:
        # Close local database readers if we created them
        if local_readCity is not readCity and local_readCity is not None:
            local_readCity.close()
        if local_readASN is not readASN and local_readASN is not None:
            local_readASN.close()

    return result_dict


# def _finditem(obj, key):
#     if key in obj: return obj[key]
#     for k, v in obj.items():
#         if isinstance(v, dict):
#             item = _finditem(v, key)
#             if item is not None:
#                 return item


def _getListKeyVal(_documents, keyGroup, keyName):
    for item, doc in _documents.items():
        if keyGroup in item:
            for item2 in doc:
                if keyName in item2['name']:
                    return item2['value']


# Create pivot table with results
from pivot_utils import create_pivot_table, print_pivot_summary, create_threat_type_pivot_table, print_threat_type_summary, get_pivot_summary_stats, get_threat_type_summary_stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A tool to gather information garding IPs')
    parser.add_argument("-f", "--file", dest='file', type=str, required=False,
                        help="File with list of IPs one per line")
    parser.add_argument("-i", "--i", dest='ip', type=str, required=False, help="Lookup single IP")
    parser.add_argument("-n", "--HitsOnly", dest='bHitsOnly', required=False, action='store_true',
                        help="Only show hits from threat feeds 'True'")
    parser.add_argument("-j", "--SkipFeeds", dest='bSkipFeeds', required=False, action='store_true',
                        help="Skip threat feed matching")
    parser.add_argument("-r", "--host", dest='host', required=False, action='store_true',
                        help="Resolve host via whois. Provide 'True'")
    parser.add_argument("-a", "--hostAPI", dest='hostAPI', required=False, action='store_true',
                        help="Resolve host via API. Provide 'True'")
    parser.add_argument("-c", "--csv", dest='csv', required=False, action='store_true', help="Output results to CSV")
    parser.add_argument("-x", "--xlsx", dest='xlsx', required=False, action='store_true',
                        help="Output results to a file in xlsx")
    parser.add_argument("-d", "--sqlite", dest='sqlite', required=False, action='store_true',
                        help="Output results to a sqlite db")
    parser.add_argument("-s", "--skip_update", dest='skip_update', required=False, action='store_true',
                        help="I'm in a hurry.. Skip downloading updated lists")
    parser.add_argument("-t", "--htmlOutput", dest='bhtmlOutput', required=False, action='store_true',
                        help="Output to html in a browser")
    parser.add_argument("-l", "--vtLookup", dest='bvtLookup', required=False, action='store_true',
                        help="VirusTotal scoring")
    parser.add_argument("-b", "--json", dest='json', required=False, action='store_true',
                        help="Output results to file in json")
    parser.add_argument("-p", "--processes", dest='num_processes', type=int, required=False, default=None,
                        help="Number of processes to use for multiprocessing (default: auto-detect)")
    parser.add_argument("-g", "--chunk-size", dest='chunk_size', type=int, required=False, default=None,
                        help="Chunk size for multiprocessing (default: auto-calculate)")
    parser.add_argument("-v", "--pivot", dest='pivot', required=False, action='store_true',
                        help="Create pivot tables: one grouped by indicators and IPs, another by threat types and IP counts")
    parser.add_argument("--allow-private", dest='allow_private', required=False, action='store_true',
                        help="Allow processing of private IP addresses (default: skip private IPs)")

    args = parser.parse_args()

    gethost = args.host
    gethostAPI = args.hostAPI
    bHitsOnly = args.bHitsOnly
    bSkipFeeds = args.bSkipFeeds
    bCheckVT = args.bvtLookup
    bAllowPrivate = args.allow_private
    strRptDT = int(time.strftime('%Y%m%d%H%M%S'))

    # Add cache folder for feeds if doesn't exist
    if not os.path.exists("cache"):
        os.makedirs("cache")

    documents = get_feeds_from_yml()

    # Always load feeds unless explicitly skipping them
    if not bSkipFeeds:
        print("Fetching feeds updates. [Update older than 24 hrs]")
        setup_feeds(args.skip_update)
        load_feeds()
        load_asn_feeds()
        
        # Debug: Show loaded threat feeds
        if threat_feeds:
            print(f"Loaded {len(threat_feeds)} threat feeds:")
            for feed_name, feed_data in list(threat_feeds.items())[:5]:  # Show first 5 feeds
                print(f"  - {feed_name}: {len(feed_data)} entries")
            if len(threat_feeds) > 5:
                print(f"  ... and {len(threat_feeds) - 5} more feeds")
        else:
            print("Warning: No threat feeds loaded!")
    else:
        print("Skipping threat feed loading (-j flag provided)")
    
    # Show private IP filtering status
    if bAllowPrivate:
        print("Private IP filtering: DISABLED (--allow-private flag provided)")
    else:
        print("Private IP filtering: ENABLED (private IPs will be skipped)")

    # seup vtApiKey
    VIRUSTOTAL_API_KEY = _getListKeyVal(documents, "api_keys", "VIRUSTOTAL_API_KEY")
    VTsleepTime = int(_getListKeyVal(documents, "api_keys", "VTsleepTime"))

    # Generate a sub list of cidr ranges from master list to speed things up later.
    print("Populating list of items from feeds with cidr ranges..")
    for key, val in threat_feeds.items():
        dicListCIDRS[key] = [item for (item) in val if '/' in item]

    if gethost:
        print("Note: Reverse lookups will increase processing time.")

    # Validate database files exist
    if not validate_database_files():
        print("Cannot proceed without required database files.")
        sys.exit(1)

    lstResults = []
    
    # Improved multiprocessing implementation
    if args.file:
        with open(args.file, "r", encoding='utf-8') as file:
            lstIps = [line.rstrip() for line in file.readlines()]
            print(f'Items to process: {len(lstIps)}\n')
            
            # Pre-filter private IPs if filtering is enabled
            if not bAllowPrivate:
                from ip_utils import filter_private_ips
                original_count = len(lstIps)
                lstIps, filtered_private_ips = filter_private_ips(lstIps, include_reason=True)
                if filtered_private_ips:
                    print(f"Filtered out {len(filtered_private_ips)} private IPs:")
                    for ip, reason in filtered_private_ips[:10]:  # Show first 10
                        print(f"  - {ip}: {reason}")
                    if len(filtered_private_ips) > 10:
                        print(f"  ... and {len(filtered_private_ips) - 10} more private IPs")
                    print(f"Remaining IPs to process: {len(lstIps)}\n")
                else:
                    print("No private IPs found in input file.\n")
            
            # Use multiprocessing.Pool for better performance and resource management
            if args.num_processes:
                num_processes = min(args.num_processes, len(lstIps))
                print(f'Using user-specified number of processes: {num_processes}')
            else:
                num_processes = min(multiprocessing.cpu_count(), len(lstIps))
                print(f'Using {num_processes} processes for parallel processing (auto-detected)')
            
            # Create a multiprocessing pool with better error handling
            try:
                with multiprocessing.Pool(processes=num_processes, 
                                        maxtasksperchild=100) as pool:
                    # Process IPs in chunks for better memory management
                    if args.chunk_size:
                        chunk_size = max(1, args.chunk_size)
                        print(f'Using user-specified chunk size: {chunk_size}')
                    else:
                        chunk_size = max(1, min(50, len(lstIps) // (num_processes * 2)))
                        print(f'Auto-calculated chunk size: {chunk_size}')
                    
                    # Create chunks of IPs
                    ip_chunks = [lstIps[i:i + chunk_size] for i in range(0, len(lstIps), chunk_size)]
                    print(f'Created {len(ip_chunks)} chunks for processing...')
                    
                    # Process chunks in parallel with progress tracking
                    total_chunks = len(ip_chunks)
                    chunk_results = []
                    
                    for i, chunk_result in enumerate(pool.imap(process_ip_chunk, [(chunk, threat_feeds, dicListCIDRS, bSkipFeeds) for chunk in ip_chunks])):
                        chunk_results.append(chunk_result)
                        if (i + 1) % max(1, total_chunks // 10) == 0:  # Show progress every 10%
                            print(f'Progress: {i + 1}/{total_chunks} chunks completed ({(i + 1) * 100 // total_chunks}%)')
                    
                    # Flatten results from all chunks
                    lstResults = []
                    for chunk_result in chunk_results:
                        lstResults.extend(chunk_result)
                        # Clear chunk result to free memory
                        del chunk_result
                    
                    # Clear chunk results list to free memory
                    del chunk_results
                    del ip_chunks
                    
                    print(f'Processed {len(lstResults)} IPs successfully')
                    
            except KeyboardInterrupt:
                print('\nInterrupted by user. Cleaning up...')
                if 'pool' in locals():
                    pool.terminate()
                    pool.join()
                sys.exit(1)
            except Exception as e:
                print(f'Error during multiprocessing: {e}')
                print('Falling back to single-threaded processing...')
                # Fallback to single-threaded processing
                city_db, asn_db = get_database_paths()
                with geoip2.database.Reader(city_db) as readCity, geoip2.database.Reader(asn_db) as readASN:
                    lstResults = []
                    for i, ip in enumerate(lstIps):
                        if i % 100 == 0:
                            print(f'Processing IP {i+1}/{len(lstIps)}...')
                        lstResults.append(ipProcess(ip, readCity, readASN))
                
    elif args.ip:
        # Single IP processing - no need for multiprocessing
        single_ip = args.ip.rstrip()
        
        # Check if single IP is private
        if not bAllowPrivate and is_private_ip(single_ip):
            reason = get_private_ip_reason(single_ip)
            print(f"Warning: {single_ip} is a private IP ({reason})")
            print("Use --allow-private flag to process private IPs")
            sys.exit(1)
        
        city_db, asn_db = get_database_paths()
        with geoip2.database.Reader(city_db) as readCity, geoip2.database.Reader(asn_db) as readASN:
            lstResults.append(ipProcess(single_ip, readCity, readASN))
    else:
        print("Provide an ip or file to process...")

    #Process VirusTotal lookups if enabled
    if bCheckVT:
        stTime = (VTsleepTime * len(lstResults)) / 60
        print(f'Processing VirusTotal lookups for {len(lstResults)} items will take approxmiatedly {stTime} minutes.')
        for result in lstResults:
            vtResults = vt_is_malicious_ip(result.ip, VIRUSTOTAL_API_KEY, VTsleepTime)
            if vtResults:
                result.vt_rep = vtResults

    df = pd.DataFrame([{
        'ip': result.ip,
        'country': result.country,
        'city': result.city,
        'asn': result.asn,
        'asn_org': result.asn_org,
        'isp': result.isp,
        'host': result.host,
        'indicators': result.indicators,
        'vt': result.vt,
        'vt_rep': result.vt_rep,
        'is_proxy': result.is_proxy,
        'notes': result.notes
    } for result in lstResults])
    
    # Setup output filename
    current_directory = os.getcwd()
    tmpOutFileName = current_directory + f"/results{strRptDT}"

    # create a Styler
    df_styled = df.style.set_properties(
        **{'font-size': '10pt', 'background-color': '#edeeef', 'border-color': 'black', 'border-style': 'solid',
           'border-width': '0px', 'border-collapse': 'collapse'}
    ).hide(axis="index")

    #console output padding
    print("")
    
    # print final results to console if anything other than HTML output
    if not args.bhtmlOutput:
        print(tabulate(df, df.columns, tablefmt="simple", showindex=False))
        print("")
        
        # Show pivot table if requested
        if args.pivot:
            print("\n" + "="*80)
            print("PIVOT TABLE VIEW - Threat Indicators by IP")
            print("="*80)
            
            pivot_df = create_pivot_table(df)
            if pivot_df is not None:
                print(tabulate(pivot_df, headers='keys', tablefmt="grid", showindex=True))
                print(f"\nPivot table shows {len(pivot_df)} IPs with threat indicators")
                
                # Use the imported function for summary
                print_pivot_summary(pivot_df)
            else:
                print("No pivot table data available.")
            
            # Show threat type pivot table
            print("\n" + "="*80)
            print("PIVOT TABLE VIEW - Threat Types by IP Count")
            print("="*80)
            
            threat_pivot_df = create_threat_type_pivot_table(df)
            if threat_pivot_df is not None:
                print(tabulate(threat_pivot_df, headers='keys', tablefmt="grid", showindex=True))
                print(f"\nThreat type pivot table shows {len(threat_pivot_df)} threat types")
                
                # Use the imported function for summary
                print_threat_type_summary(threat_pivot_df)
            else:
                print("No threat type pivot table data available.")

    # Output to file options
    if args.bhtmlOutput:
        # If output to html is selected write to html file and open a new browser window
        tmpOutHtml = tmpOutFileName + '.html'
        with open(tmpOutHtml, 'w', encoding='utf-8') as f:
            # Write HTML header
            print("<!DOCTYPE html>", file=f)
            print("<html><head>", file=f)
            print("<title>IP Enrichment Results</title>", file=f)
            print("<style>", file=f)
            print("body { font-family: Arial, sans-serif; margin: 20px; }", file=f)
            print("h1, h2 { color: #333; }", file=f)
            print("table { margin: 20px 0; border-collapse: collapse; width: 100%; }", file=f)
            print("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }", file=f)
            print("th { background-color: #f2f2f2; font-weight: bold; }", file=f)
            print("tr:nth-child(even) { background-color: #f9f9f9; }", file=f)
            print(".pivot-section { margin: 30px 0; }", file=f)
            print(".pivot-link { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }", file=f)
            print(".pivot-link:hover { background-color: #0056b3; }", file=f)
            print("</style>", file=f)
            print("</head><body>", file=f)
            
            # Main results table
            print("<h1>IP Enrichment Results</h1>", file=f)
            
            # Add pivot report link at the top if pivot tables are requested
            if args.pivot:
                pivot_html = tmpOutFileName + '_pivot_report.html'
                print(f"<a href='{pivot_html}' class='pivot-link' target='_blank'>📊 View Pivot Report (Opens in New Tab)</a>", file=f)
            
            print(df_styled.to_html(), file=f)
            print("</body></html>", file=f)
        
        webbrowser.open_new('file://' + tmpOutHtml)
        print(f"Results written to {tmpOutHtml}")
        
        # Create separate pivot report HTML file if requested
        if args.pivot:
            pivot_report_html = tmpOutFileName + '_pivot_report.html'
            with open(pivot_report_html, 'w', encoding='utf-8') as f:
                # Write HTML header for pivot report
                print("<!DOCTYPE html>", file=f)
                print("<html><head>", file=f)
                print("<title>IP Enrichment - Pivot Report</title>", file=f)
                print("<style>", file=f)
                print("body { font-family: Arial, sans-serif; margin: 20px; }", file=f)
                print("h1, h2 { color: #333; }", file=f)
                print("table { margin: 20px 0; border-collapse: collapse; width: 100%; }", file=f)
                print("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }", file=f)
                print("th { background-color: #f2f2f2; font-weight: bold; }", file=f)
                print("tr:nth-child(even) { background-color: #f9f9f9; }", file=f)
                print(".pivot-section { margin: 30px 0; }", file=f)
                print(".back-link { background-color: #6c757d; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }", file=f)
                print(".back-link:hover { background-color: #545b62; }", file=f)
                print(".summary-stats { background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }", file=f)
                print("</style>", file=f)
                print("</head><body>", file=f)
                
                print("<h1>IP Enrichment - Pivot Report</h1>", file=f)
                print(f"<a href='{tmpOutHtml}' class='back-link'>← Back to Main Results</a>", file=f)
                
                # First pivot table: IPs by threat types
                pivot_df = create_pivot_table(df)
                if pivot_df is not None:
                    print("<div class='pivot-section'>", file=f)
                    print("<h2>Pivot Table: Threat Indicators by IP</h2>", file=f)
                    print("<p>This table shows each IP and the count of different threat types found.</p>", file=f)
                    
                    # Add summary statistics
                    stats = get_pivot_summary_stats(pivot_df)
                    if stats:
                        print("<div class='summary-stats'>", file=f)
                        print(f"<strong>Summary:</strong> {stats['total_ips_with_threats']} IPs with threats, {stats['total_threat_occurrences']} total threat occurrences, {stats['avg_threats_per_ip']:.2f} average threats per IP", file=f)
                        print("</div>", file=f)
                    
                    pivot_styled = pivot_df.style.set_properties(
                        **{'font-size': '10pt', 'background-color': '#edeeef', 'border-color': 'black', 'border-style': 'solid',
                           'border-width': '0px', 'border-collapse': 'collapse'}
                    ).hide(axis="index")
                    print(pivot_styled.to_html(), file=f)
                    print("</div>", file=f)
                
                # Second pivot table: threat types by IP count
                threat_pivot_df = create_threat_type_pivot_table(df)
                if threat_pivot_df is not None:
                    print("<div class='pivot-section'>", file=f)
                    print("<h2>Pivot Table: Threat Types by IP Count</h2>", file=f)
                    print("<p>This table shows each threat type and how many IPs are affected by it.</p>", file=f)
                    
                    # Add summary statistics
                    threat_stats = get_threat_type_summary_stats(threat_pivot_df)
                    if threat_stats:
                        print("<div class='summary-stats'>", file=f)
                        print(f"<strong>Summary:</strong> {threat_stats['total_threat_types']} threat types, {threat_stats['total_ips_affected']} total IPs affected, {threat_stats['avg_ips_per_threat_type']:.2f} average IPs per threat type", file=f)
                        print("</div>", file=f)
                    
                    threat_pivot_styled = threat_pivot_df.style.set_properties(
                        **{'font-size': '10pt', 'background-color': '#edeeef', 'border-color': 'black', 'border-style': 'solid',
                           'border-width': '0px', 'border-collapse': 'collapse'}
                    )
                    print(threat_pivot_styled.to_html(), file=f)
                    print("</div>", file=f)
                
                print("</body></html>", file=f)
            
            print(f"Pivot report written to {pivot_report_html}")
            
            # Keep the separate pivot HTML files for backward compatibility
            pivot_df = create_pivot_table(df)
            if pivot_df is not None:
                pivot_html = tmpOutFileName + '_pivot.html'
                pivot_styled = pivot_df.style.set_properties(
                    **{'font-size': '10pt', 'background-color': '#edeeef', 'border-color': 'black', 'border-style': 'solid',
                       'border-width': '0px', 'border-collapse': 'collapse'}
                ).hide(axis="index")
                
                with open(pivot_html, 'w', encoding='utf-8') as file:
                    print(pivot_styled.to_html(), file=file)
                print(f"Pivot table written to {pivot_html}")
    
    if args.csv:
        df.to_csv(f"{tmpOutFileName}.csv", index=False, header=True)
        print(f"Results written to {tmpOutFileName}.csv")
        
        # Add pivot table CSV if requested
        if args.pivot:
            pivot_df = create_pivot_table(df)
            if pivot_df is not None:
                pivot_df.to_csv(f"{tmpOutFileName}_pivot.csv")
                print(f"Pivot table written to {tmpOutFileName}_pivot.csv")
            
            # Add threat type pivot table CSV
            threat_pivot_df = create_threat_type_pivot_table(df)
            if threat_pivot_df is not None:
                threat_pivot_df.to_csv(f"{tmpOutFileName}_threat_types_pivot.csv")
                print(f"Threat type pivot table written to {tmpOutFileName}_threat_types_pivot.csv")
    
    if args.xlsx:
        df_styled.to_excel(f"{tmpOutFileName}.xlsx", sheet_name='results', index=False, header=True)
        print(f"Results written to {tmpOutFileName}.xlsx")
        
        # Add pivot table to Excel if requested
        if args.pivot:
            pivot_df = create_pivot_table(df)
            if pivot_df is not None:
                with pd.ExcelWriter(f"{tmpOutFileName}.xlsx", engine='openpyxl', mode='a') as writer:
                    pivot_df.to_excel(writer, sheet_name='pivot_table')
                print(f"Pivot table added to {tmpOutFileName}.xlsx")
            
            # Add threat type pivot table to Excel
            threat_pivot_df = create_threat_type_pivot_table(df)
            if threat_pivot_df is not None:
                with pd.ExcelWriter(f"{tmpOutFileName}.xlsx", engine='openpyxl', mode='a') as writer:
                    threat_pivot_df.to_excel(writer, sheet_name='threat_types_pivot')
                print(f"Threat type pivot table added to {tmpOutFileName}.xlsx")
    
    if args.json:
        df.to_json(f"{tmpOutFileName}.json", index=False)
        print(f"Results written to {tmpOutFileName}.json")
        
        # Add pivot table JSON if requested
        if args.pivot:
            pivot_df = create_pivot_table(df)
            if pivot_df is not None:
                pivot_df.to_json(f"{tmpOutFileName}_pivot.json")
                print(f"Pivot table written to {tmpOutFileName}_pivot.json")
            
            # Add threat type pivot table JSON
            threat_pivot_df = create_threat_type_pivot_table(df)
            if threat_pivot_df is not None:
                threat_pivot_df.to_json(f"{tmpOutFileName}_threat_types_pivot.json")
                print(f"Threat type pivot table written to {tmpOutFileName}_threat_types_pivot.json")
    
    if args.sqlite:
        # save results to sqlitedb
        conn = sqlite3.connect(f"{tmpOutFileName}.sqlitedb")
        df.to_sql('results', conn, if_exists='replace', index=False)
        
        # Add pivot table to SQLite if requested
        if args.pivot:
            pivot_df = create_pivot_table(df)
            if pivot_df is not None:
                pivot_df.to_sql('pivot_table', conn, if_exists='replace', index=True)
            
            # Add threat type pivot table to SQLite
            threat_pivot_df = create_threat_type_pivot_table(df)
            if threat_pivot_df is not None:
                threat_pivot_df.to_sql('threat_types_pivot', conn, if_exists='replace', index=True)
        
        conn.close()
        print(f"Results saved to {tmpOutFileName}.sqlitedb")

    print("\n Lookups complete.")
