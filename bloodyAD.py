# Credits to aclpwn
import argparse
from bloodyAD import ldap

def main():
    parser = argparse.ArgumentParser(description='Active Directory Privilege Escalation Framework')
    parser._optionals.title = 'Main options'
    parser._positionals.title = 'Required options'

    #Main parameters
    authentication_group = parser.add_argument_group('AD authentication options')
    authentication_group.add_argument('-k', '--kerberos', action='store_true', default=False)
    authentication_group.add_argument('url', help='LDAP URL: ldap://my.dc.local or ldaps://172.16.1.3\ntest')
    authentication_group.add_argument('domain')
    authentication_group.add_argument('username', help='Username used with NTLM')
    authentication_group.add_argument('password', help='Cleartext password or LMHASH:NTHASH')
    subparsers = parser.add_subparsers()
    
    bloodhound_parser = subparsers.add_parser('automatic', help='BloodHound automation help')
    bloodhound_parser.add_argument('-y','--yes', action='store_true', help='Automatic yes to prompts; assume yes for the escalation path and will automatically perform it')
    bloodhound_parser.add_argument('-f','--from',metavar='SOURCE', help='Source object to start the path (user, computer, domain). The format is the same as the extra properties name in BloodHound. Example for a user: user@domain.local')
    bloodhound_parser.add_argument('-t','--to', metavar='DESTINATION', help='Target object to escalate to (for example a group/domain). Example: computer.domain.local or domain.local')

    #DB parameters
    database_group = bloodhound_parser.add_argument_group('Database options')
    database_group.add_argument('--database', default='localhost', help='The host neo4j is running on. Default: localhost.')
    database_group.add_argument('-du', '--database-user', default='neo4j', help='Neo4j username to use')
    database_group.add_argument('-dp', '--database-password', help='Neo4j password to use')

    #LDAP parameters
    ldap_parser = subparsers.add_parser('manual', help='',formatter_class=argparse.RawTextHelpFormatter)
    ldap_parser.add_argument('function', help="Function to call with args following it:\n"
    "\t addUserToGroup <member> <group>\n"
    "\t addDomainSync <sAMAccountName>\n"
    "\t setShadowCredentials <sAMAccountName>\n"
    "\t changePassword <sAMAccountName> <new_password>")
    ldap_parser.add_argument('params', help='Function parameters', nargs='+')

    args = parser.parse_args()

    conn = ldap.ldapConnect(args.url, args.domain, args.username, args.password, args.kerberos)

    if hasattr(args, 'function'):
        getattr(ldap,args.function)(conn, args.params)
        

if __name__ == '__main__':
    main()
