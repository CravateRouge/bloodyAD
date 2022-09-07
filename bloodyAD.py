#!/usr/bin/env python3
import sys
import argparse
from bloodyAD import functions, ConnectionHandler


def main():
    parser = argparse.ArgumentParser(description='AD Privesc Swiss Army Knife', formatter_class=argparse.RawTextHelpFormatter)

    parser._optionals.title = 'Main options'
    parser._positionals.title = 'Required options'

    parser.add_argument('-d', '--domain', help='Domain used for NTLM authentication')
    parser.add_argument('-u', '--username', help='Username used for NTLM authentication')
    parser.add_argument('-p', '--password', help='Cleartext password or LMHASH:NTHASH for NTLM authentication')
    parser.add_argument('-k', '--kerberos', action='store_true', default=False)
    parser.add_argument('-c', '--certificate', help='Certificate authentication, e.g: "path/to/key:path/to/cert"')
    parser.add_argument('-s', '--secure', help='Try to use LDAP over TLS aka LDAPS (default is LDAP)', action='store_true', default=False)
    parser.add_argument('--host', help='Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)')

    # Find list of functions and their arguments in ldap.py
    # And add them all as subparsers
    subparsers = parser.add_subparsers(title="Commands", help='Function to call')
    for name, f in functions:
        subparser = subparsers.add_parser(name, prog=f.__doc__)
        subparser.add_argument('func_args', nargs='*')
        subparser.set_defaults(func=f)

    args = parser.parse_args()

    if not 'func' in args :
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    # Get the list of parameters to provide to the command
    param_names = args.func.__code__.co_varnames[1:args.func.__code__.co_argcount]
    param_values = args.func_args

    if len(param_values) > len(param_names):
        print("You provided too many arguments\n")
        print(args.func.__name__ + ':')
        print(args.func.__doc__)
        sys.exit(1)

    params = {param_names[i]: param_values[i] for i in range(len(param_values))}

    # Launch the command
    conn = ConnectionHandler(args=args)
    args.func(conn, **params)


if __name__ == '__main__':
    main()
