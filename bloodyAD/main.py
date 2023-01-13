#!/usr/bin/env python3
from bloodyAD import cli_modules
from bloodyAD import functions, ConnectionHandler
import sys, argparse

# For dynamic argparse
from inspect import getmembers, isfunction, signature
from pkgutil import iter_modules


def main():
    parser = argparse.ArgumentParser(description="AD Privesc Swiss Army Knife")

    parser.add_argument("-d", "--domain", help="Domain used for NTLM authentication")
    parser.add_argument(
        "-u", "--username", help="Username used for NTLM authentication"
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Cleartext password or LMHASH:NTHASH for NTLM authentication",
    )
    parser.add_argument("-k", "--kerberos", action="store_true", default=False)
    parser.add_argument(
        "-c",
        "--certificate",
        help='Certificate authentication, e.g: "path/to/key:path/to/cert"',
    )
    parser.add_argument(
        "-s",
        "--secure",
        help="Try to use LDAP over TLS aka LDAPS (default is LDAP)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--host",
        help="Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)",
    )

    # Find list of functions and their arguments in modules.py
    # And add them all as subparsers
    subparsers = parser.add_subparsers(title="Commands")
    for name, f in functions:
        subparser = subparsers.add_parser(name, prog=f.__doc__)
        subparser.add_argument("func_args", nargs="*")
        subparser.set_defaults(func=f)

    # Iterates all submodules in module package and creates one parser per submodule
    for importer, submodname, ispkg in iter_modules(cli_modules.__path__):
        subparser = subparsers.add_parser(
            submodname, help=f"[{submodname.upper()}] function category"
        )
        subsubparsers = subparser.add_subparsers(title=f"{submodname} commands")
        submodule = importer.find_spec(submodname).loader.load_module()
        for function_name, function in getmembers(submodule, isfunction):
            # Doesn't take into account function imported in the module
            if function.__module__ != submodname:
                continue

            function_doc, params_doc = doc_parser(function.__doc__)
            # This formatter class prints default values
            subsubparser = subsubparsers.add_parser(
                function_name,
                help=function_doc,
                formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            )
            # Gets function signature to extract parameters default values
            func_signature = signature(function)
            for param_name, param_value, param_doc in zip(
                function.__annotations__.keys(),
                function.__annotations__.values(),
                params_doc,
                strict=True,
            ):
                parser_args = {}

                # Fetches help from param_doc, if param_name doesn't match
                # name in param_doc, raises exception
                try:
                    param_doc = param_doc.split(f":param {param_name}: ")[1]
                except IndexError:
                    print(f"[-] param_name '{param_name}' doesn't match '{param_doc}'")
                    raise
                parser_args["help"] = param_doc

                # If parameter has a default value, then it will be an optional argument
                param_signature = func_signature.parameters.get(param_name)
                param_name = param_name.replace("_", "-")
                if param_signature.default is param_signature.empty:
                    arg_name = param_name
                else:
                    arg_name = f"--{param_name}"
                    parser_args["default"] = param_signature.default

                # If param_type is not a string describing a type it's a literal with a restricted set of values
                if param_value.__name__ == "Literal":
                    parser_args["choices"] = param_value.__args__
                    parser_args["type"] = type(param_value.__args__[0])
                else:
                    if param_value.__name__ == "bool":
                        parser_args["action"] = "store_true"
                    else:
                        parser_args["type"] = param_value

                subsubparser.add_argument(arg_name, **parser_args)
            # If a function name is provided in cli, arg.func will exist with function as value
            subsubparser.set_defaults(func=function)

    args = parser.parse_args()

    if "func" not in args:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Get the list of parameters to provide to the command
    param_names = args.func.__code__.co_varnames[1 : args.func.__code__.co_argcount]
    if "func_args" in args:
        param_values = args.func_args
        if len(param_values) > len(param_names):
            print("You provided too many arguments\n")
            print(args.func.__name__ + ":")
            print(args.func.__doc__)
            sys.exit(1)
        params = {param_names[i]: param_values[i] for i in range(len(param_values))}
    else:
        params = {param_name: vars(args)[param_name] for param_name in param_names}

    # Launch the command
    conn = ConnectionHandler(args=args)
    args.func(conn, **params)


# Gets unparsed doc and returns a tuple of two values
# first is function description (starts at the beginning of the string and ends before two newlines)
# second is a list of parameter descriptions
# (other part of the string, one parameter description per line, starting with :param param_name:)
def doc_parser(doc):
    doc_parsed = doc.splitlines()

    return doc_parsed[1], doc_parsed[3:-1]


if __name__ == "__main__":
    main()
