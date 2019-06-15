#!/usr/env python

import time
import json
import sys
import io
from urllib import urlopen

reload(sys)
sys.setdefaultencoding('utf8') #set encoding


if len(sys.argv) < 3:
	print ('*** GEO IP LOOKUP TOOL ***')
	print ('[*] Rudi Peck - www.g-cpartners.com')	
	print ('[*] Usage: python iplookup.py IPList.txt Out.csv')
	
	exit(0)
else:
	iplist = sys.argv[1]
	csvfile = sys.argv[2]


outFile = io.open(csvfile, 'a', encoding='utf8')

#HEADER INFORMATION
outFile.write(u"ip,country,region,city,isp,org")
outFile.write(u"\n")

#Process IP List
with open(iplist, "r") as iplist:
    
    for ip in iplist:
        if "127.0.0.1" in ip:
            continue
        if ip.startswith("172.16."):
            continue
        if ip.startswith("10."):
            continue
        if ip.startswith("192.168."):
            continue
        
	GeoInfo = ""
	chkAddress = "http://ip-api.com/json/" + ip	#Build Query String	
	ipquery = urlopen(chkAddress).read()         	#Query IP Address
	
	ipresults = json.loads(ipquery)			#load json result
	
	if "private range" not in ipresults:
		print ipresults
		GeoInfo=ipresults["query"] + ","
		if ipresults["status"] != "fail":
			GeoInfo+=ipresults["country"] + ","
			GeoInfo+=ipresults["region"] + ","
			GeoInfo+=ipresults["city"] + ","
			GeoInfo+=ipresults["isp"] + ","
			GeoInfo+=ipresults["org"] 
		print GeoInfo
		outFile.write(GeoInfo)	#Write query result to csv
		outFile.write(u"\n")	#unicode newline
			
		#need to sleep, can only run max of 150 queries a minute or get banned
		time.sleep(.400)
        
outFile.close()
