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
import argparse

# Developed by David Dym @ easymetadata.com v1 07/05/2020
# Updated dd @ easymetadata.com v5b 10/29/2020
#
# This script uses geoip db's to enrich ip address location information.
# This script downloads various ip lists to provide threat intel for ipset
# Requires python3

#sys.setdefaultencoding('utf8') #set encoding

whois_cache = []
fqdn_cache = {}
firehole_list = []
firehole_anon = []
firehole_proxies = []
firehole_tor_exits = []
firehole_bambenek_qakbot = []
firehole_abusers_1d = []
firehole_bi_any_0_1d = []
alienvault_reputation = []
fireholelist_ssl_proxies_30d = []

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
            with geoip2.database.Reader('GeoLite2-ASN.mmdb') as reader:
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

def main():
    parser = argparse.ArgumentParser(description='A tool to gather information garding IPs')
    parser.add_argument("-f", "--file", dest='file', type=str, required=True, help="File with list of IPs one per line")
    parser.add_argument("-n", "--HitsOnly", dest='bHitsOnly', required=False,action='store_true', help="Only show hits from threat feeds 'True'")
    parser.add_argument("-r", "--FQDN", dest='FQDN', required=False,action='store_true', help="Resolve FQDN. Provide 'True'")

    args = parser.parse_args()

    GetFireHoleLists("fireholelist.txt","https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",firehole_list)
    GetFireHoleLists("fireholelist_anon.txt","https://iplists.firehol.org/files/firehol_anonymous.netset",firehole_anon)
    GetFireHoleLists("fireholelist_proxies.txt","https://iplists.firehol.org/files/firehol_proxies.netset",firehole_proxies)
    GetFireHoleLists("fireholelist_tor_exits.txt","https://iplists.firehol.org/files/tor_exits.ipset",firehole_tor_exits)
    GetFireHoleLists("fireholelist_bambenek_qakbot.txt","https://iplists.firehol.org/files/bambenek_qakbot.ipset",firehole_bambenek_qakbot) 
    GetFireHoleLists("fireholelist_abusers_1d.txt","https://iplists.firehol.org/files/firehol_abusers_1d.netset",firehole_abusers_1d)
    GetFireHoleLists("fireholelist_bi_any_0_1d.txt","https://iplists.firehol.org/files/bi_any_0_1d.ipset",firehole_bi_any_0_1d)
    GetFireHoleLists("fireholelist_alienvault_reputation.txt","https://iplists.firehol.org/files/alienvault_reputation.ipset",alienvault_reputation)
    GetFireHoleLists("fireholelist_ssl_proxies_30d.txt","https://iplists.firehol.org/files/sslproxies_30d.ipset",fireholelist_ssl_proxies_30d)
    loadFQDNcache()

    print("IP, City, Country, ASN Org, hostname, FireHole Indicators")

    with open(args.file, "r") as f:
        readerCity = geoip2.database.Reader('GeoLite2-City.mmdb')

        for ip in f:
            newRow = ""
            icount = 0
            row = getInfo(ip.rstrip(),readerCity)
            
            fh = CheckFireHoleList_cidr(ip.rstrip(),firehole_list,"level 1")

            if args.FQDN:
                row += ", " + CheckFQDN(ip.rstrip())
            
            fhresult = ""

            if fh:
                fhresult += fh + "|"
            if ip in firehole_anon:
                fhresult += "anonymous|"
            if ip in firehole_proxies:
                fhresult += "proxies"
            if ip in firehole_tor_exits:
                fhresult += "tor_exit_yd"
            if ip in firehole_bambenek_qakbot:
                fhresult += "bambenek_qakbot"
            if ip in firehole_abusers_1d:
                fhresult += "abusers_1d"
            if ip in firehole_bi_any_0_1d:
                fhresult += "bi_any_0_1d"
            if ip in alienvault_reputation:
                fhresult += "alienvault_reputation"
            if ip in fireholelist_ssl_proxies_30d:
                fhresult += "ssl_proxies_30d"
            if fhresult:
                row += "," + fhresult.rstrip("|")

            if fhresult and args.bHitsOnly:
                print (row)
            else:
                if not args.bHitsOnly:
                    print (row)

    # save fqdn cache
    writeFQDNcache()

if True:
    main()