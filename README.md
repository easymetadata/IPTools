# IPEnrich

This tool provides geo IP information and threat feed mapping of your choosing. It's multithreaded for spead.

**Configuration and Feeds**

The list of feeds are defined in the list.yml. Lists are primarily FireHol and misp feeds but can be any ip list.  Feel free to suggest more.

```
usage: ipEnrich.py [-h] [-f FILE] [-i IP] [-n] [-j] [-r] [-o OUTFILE] [-x] [-s]

A tool to gather information garding IPs

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File with list of IPs one per line
  -i IP, --i IP         Lookup single IP
  -n, --HitsOnly        Only show hits from threat feeds 'True'
  -j, --SkipFeeds       Skip threat feed matching
  -r, --FQDN            Resolve FQDN. Provide 'True'
  -o OUTFILE, --outfile OUTFILE
                        Output file name [default CSV]
  -x, --xlsx            Output results to a file in xlsx
  -s, --skip_update     I'm in a hurry.. Skip downloading updated lists.
```

**Examples** 

Geo ip lookups with feed matching 
```  python3 ipEnrich.py -f file.txt (use a list of ip's from a file)
  python3 ipEnrich.py -i IP  (lookup a single ip)
```

Only geo ip lookups
```  python3 ipEnrich.py -j -f file.txt 
  python3 ipEnrich.py -j -i IP 
```

For ip geo lookups with threat feeds with xlsx output 
```
python3 ipEnrich.py -f test_iplist_small.txt -o results111.csv -x 
```

# Disposable email domain check

Check's email domains from feed enrichment to see if email is a disposable email

Developed by David Dym
