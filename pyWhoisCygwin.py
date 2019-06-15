#!/usr/bin/env python
import sys
import subprocess
import cStringIO

ip = sys.argv[1]
subProc = "C:\\cygwin64\\bin\\whois.exe"
#result = ""
try:
    result = cStringIO.StringIO()
    rsult = subprocess.Popen([subProc], shell=True, stdout=result)
except subprocess.CalledProcessError as e:
    return_code = e.returncode




#cmd = "C:\\cygwin64\\bin\\whois.exe"
#process = subprocess.Popen(cmd, stdout=subprocess.PIPE, creationflags=0x08000000)
#process.wait()

#print stdout
#print result
