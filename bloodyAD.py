# Credits to aclpwn
import argparse
from inspect import getmembers, isfunction
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

    # Find list of functions and their arguments in ldap.py
    # And add them all as subparsers
    subparsers = parser.add_subparsers(title="Commands", help='Function to call')
    funcs = getmembers(ldap, isfunction)
    for name, f in funcs:
        subparser = subparsers.add_parser(name, prog=f.__doc__)
        func_args = f.__code__.co_varnames[1:f.__code__.co_argcount]
        for func_arg in func_args:
            subparser.add_argument(func_arg)
            subparser.set_defaults(func=f)

    args = parser.parse_args()

    # Get the list of parameters to provide to the command
    param_names = args.func.__code__.co_varnames[1:args.func.__code__.co_argcount]
    params = [getattr(args, p) for p in param_names]

    # Launch the command
    if args.func.__name__ == 'rpcChangePassword':
        ldap.rpcChangePassword(args.domain, args.username, args.password, args.host, *args.params)
    else:
        url = args.scheme + '://' + args.host
        conn = ldap.ldapConnect(url, args.domain, args.username, args.password, args.kerberos)
        args.func(conn, *params)

        
if __name__ == '__main__':
    main()
