#!/usr/env python

import time
import json
import sys
import os
from os import path
import io
import socket
import csv
import wget
from urllib import urlopen
from datetime import datetime, timedelta

#from netaddr import IPNetwork, IPAddress
#from netaddr import *

reload(sys)
sys.setdefaultencoding('utf8') #set encoding

if len(sys.argv) < 2:
    print ('*** GEO IP LOOKUP TOOL ***')
    print ('Ddym rewrite v4d 10/26/18')
    print ('[*] Usage for csv headers: python iplookup.py ListWithIPs.csv')
    print ('[*] Usage to process: python iplookup.py ListWithIPs.csv <#>')
    
    exit(0)
else:
    iplist = sys.argv[1]

domainlist = []
disposablelists = {'wildcard.json':'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/wildcard.json',
                   'index.json':'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
                   'disposable_email_blocklist.conf':'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf'}

def LoadDisposableEmailList():
    for key, val in disposablelists.items():
        if ".json" in key:
            try:
                with open(key,'r') as inF:
                    j = json.load(inF)
                    for row in j:
                        domainlist.append(row)
            except:
                print "not json: " + item
        else:
            #not json
            with open(key,'r') as inF:
                for row in inF:
                    domainlist.append(row)
        print "loaded: " + key

def GetEmailList():

    #check age of file
    for key, val in disposablelists.items():
        day = datetime.now() - timedelta(days=1)
        filetime = datetime.fromtimestamp(path.getctime(key))
        if filetime < day:
            if path.exists(key):
                os.remove(key)

    for key, val in disposablelists.items():
        if not path.exists(key):
            wget.download(val,key)
            print " [downloaded: " + key + "]"



def CheckMatchEmailList(objS):
    for item in domainlist:
        #print item
        if item == objS:
            return objS + ", " + item
    return ""

GetEmailList()
LoadDisposableEmailList()

#Process IP List
with open(iplist, "rb") as f:
    newRow = ""

    print "------------"
    print "keyword, hit"

    for row in f:
        newRow = ""
        hit = CheckMatchEmailList(row.strip())
        if hit:
            print hit

