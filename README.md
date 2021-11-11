# IPEnrich
Multithreaded IP information lookups. Provides geo IP information and threat feed mapping of your choosing. 

List of threat feeds is defined in the list.yml. Lists are primarily FireHol and misp feeds. Any IP list can be used. Feel free to suggest more.

**Usage** <br>
If you want full lookup against feeds <br>
python3 ipEnrich.py -f file.txt <br>
python3 ipEnrich.py -i IP <br>
 <br>
If you just want geo location against ip's <br>
python3 ipEnrich.py -j -f file.txt <br>
python3 ipEnrich.py -j -i IP <br>

# Disposable email domain check
Check's email domains from feed enrichment to see if email is a disposable email

Developed by David Dym @ easymetadata.com
