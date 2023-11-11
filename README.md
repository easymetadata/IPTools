# IPEnrich

This tool provides geo IP information and threat feed mapping of your choosing. It's multithreaded for spead.

**Key features**
```
  IP geo lookups (requires free geolite2 db's)
  ASN matching based on bad_asn feed
  Threat feed matching (defined in list.yml) - No guarantees of accuracy. Fully customizable
    -Feeds update every 24hrs by default. You can set it to whatever interval you choose
  VT lookups
  Reverse lookup (note this could alert on DNS)
  Output results to CSV, Excel, HTML or Sqlite
```
**Configuration and Feeds**

The list of feeds are defined in the list.yml. Lists are primarily FireHol and misp feeds but can be any ip list.  Feel free to suggest more.

```
usage: ipEnrich.py [-h] [-f FILE] [-i IP] [-n] [-j] [-r] [-c] [-x] [-d] [-s] [-t] [-l]

A tool to gather information garding IPs

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File with list of IPs one per line
  -i IP, --i IP         Lookup single IP
  -n, --HitsOnly        Only show hits from threat feeds 'True'
  -j, --SkipFeeds       Skip threat feed matching
  -r, --FQDN            Resolve FQDN. Provide 'True'
  -c, --csv             Output results to CSV
  -x, --xlsx            Output results to a file in xlsx
  -d, --sqlite          Output results to a sqlite db
  -s, --skip_update     I'm in a hurry.. Skip downloading updated lists
  -t, --htmlOutput      Output to html in a browser
  -l, --vtLookup        VirusTotal scoring

*Note: Output with empty columns are removed automatically
```

**Examples** 

Console output (basic options single ip):
```
python ipEnrich.py -i 1.1.1.1
                 
Fetching new and updated feeds... [Update older than 24 hrs]
Populating list of items from feeds with cidr ranges..
IP       Country      ASN  ASN Org
-------  ---------  -----  -------------
1.1.1.1  Australia  13335  CLOUDFLARENET
```

Lookup ip info with threat feeds (defined in list.yml), VirusTotal reputation. Output to html that is opened in browser.
  Note: VT needs your api key in lists.yml. For the free tier of VT you get capped at 500 lookups a day.
```
  python ipEnrich.py -f iplist.txt -l -t
```
![image](https://github.com/easymetadata/IPTools/assets/5246428/f6f2f9f2-2fad-4834-aa30-de4696a17aa9)



Geo ip lookups with feed matching 
```
  python3 ipEnrich.py -f file.txt (use a list of ip's from a file)
  python3 ipEnrich.py -i IP  (lookup a single ip)
```

Only geo ip lookups
```
  python3 ipEnrich.py -j -f file.txt 
  python3 ipEnrich.py -j -i IP 
```

For lookups with output in various formats csv, xlsx and sqlite 
```
python3 ipEnrich.py -f ip_list.txt -c -x -d   
```

# Disposable email domain check

Check's email domains from feed enrichment to see if email is a disposable email

Developed by David Dym
