#!/usr/env python

import time
import json
import sys
import io
import socket
from urllib import urlopen

reload(sys)
sys.setdefaultencoding('utf8') #set encoding


if len(sys.argv) < 2:
	print ('*** GEO IP LOOKUP TOOL ***')
	print ('[*] Rudi Peck - www.g-cpartners.com')	
	print ('[*] Usage: python iplookup.py IPList.txt Out.csv')
	
	exit(0)
else:
	iplist = sys.argv[1]

#HEADER INFORMATION


#Process IP List
with open(iplist, "r") as iplist:
    
    for ip in iplist:
        GeoInfo = ""
        hostdns = ""
        
        try:
            data = socket.gethostbyaddr(ip.strip())
            hostdns = repr(data[0])
            
        except:
            hostdns = ""
        #print ip

        try:
            chkAddress = "http://pro.ip-api.com/json/" + ip.strip() + '?key=OyLXtLX41aYZ2P1'   #Build Query String    
            ipquery = urlopen(chkAddress).read()             #Query IP Address
        
            ipresults = json.loads(ipquery)            #load json result

            GeoInfo=ipresults["query"] + "|"    
            GeoInfo+=ipresults["country"] + "|"
            GeoInfo+=ipresults["region"] + "|"
            GeoInfo+=ipresults["city"] + "|"
            GeoInfo+=ipresults["isp"] + "|"
            GeoInfo+=ipresults["org"] 

        except:
            continue
            #GeoInfo = ip + " - IP is private or invalid;"
        
        if hostdns:
            GeoInfo += '|' + hostdns.replace("'","")
        print GeoInfo

            
    #need to sleep, can only run max of 150 queries a minute or get banned
        #time.sleep(300)
