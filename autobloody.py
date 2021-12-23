#!/usr/bin/python 
import argparse, json
from autobloody import automation

def main():
    parser = argparse.ArgumentParser(description='Active Directory Privilege Escalation Framework', formatter_class=argparse.RawTextHelpFormatter)

    # Exploitation parameters
    parser.add_argument('-d', '--domain', help='Domain used for NTLM authentication')
    parser.add_argument('-u', '--username', help='Username used for NTLM authentication')
    parser.add_argument('-p', '--password', help='Cleartext password or LMHASH:NTHASH for NTLM authentication')
    parser.add_argument('-k', '--kerberos', action='store_true', default=False)
    parser.add_argument('-s', '--scheme', help='Use LDAP over TLS (default is LDAP)', choices=['ldap', 'ldaps', 'rpc'], default="ldap")
    parser.add_argument('--host', help='Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)', required=True)
    parser.add_argument('--path', help='Path file (to generate with pathgen.py)', default="path.json")

    args = parser.parse_args()
    automate = automation.Automation(args)
    with open(args.path, 'r') as f:
        automate.exploit(json.load(f))

if __name__ == '__main__':
    main()
