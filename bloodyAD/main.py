#!/usr/bin/env python3
from bloodyAD import cli_modules, ConnectionHandler, utils
import sys, argparse, types

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
    parser.add_argument(
        "-v",
        "--verbose",
        help="Adjust output verbosity",
        choices=["QUIET", "INFO", "DEBUG"],
        default="INFO",
    )

    subparsers = parser.add_subparsers(title="Commands")
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
                if param_signature.default is param_signature.empty:
                    arg_name = param_name
                else:
                    # If param with one letter only add just one dash
                    if len(param_name) < 2:
                        arg_name = f"-{param_name}"
                    else:
                        param_name = param_name.replace("_", "-")
                        arg_name = f"--{param_name}"
                    parser_args["default"] = param_signature.default

                # If param_type is not a string describing a type it's a literal with a restricted set of values
                if "Literal" in str(param_value):
                    parser_args["choices"] = param_value.__args__
                    parser_args["type"] = type(param_value.__args__[0])
                else:
                    if param_value.__name__ == "bool":
                        parser_args["action"] = "store_true"
                    elif param_value.__name__ == "list":
                        parser_args["action"] = "append"
                        parser_args["type"] = str
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
    params = {param_name: vars(args)[param_name] for param_name in param_names}

    LOGGING_LEVELS = {"QUIET": 50, "INFO": 20, "DEBUG": 10}
    utils.LOG.setLevel(LOGGING_LEVELS[args.verbose])
    # Launch the command
    conn = ConnectionHandler(args=args)
    output = args.func(conn, **params)

    # Prints output, will print it directly if it's not an iterable
    # Output is expected to be of type [{name:[members]},{...}...]
    # If it's not, will print it raw
    output_type = type(output)
    if not output or output_type == bool:
        return

    if output_type not in [list, dict, types.GeneratorType]:
        print("\n" + output)
        return

    for entry in output:
        print()
        for attr_name, attr_val in entry.items():
            entry_str = print_entry(attr_name, attr_val)
            if entry_str:
                print(f"{attr_name}: {entry_str}")


# Gets unparsed doc and returns a tuple of two values
# first is function description (starts at the beginning of the string and ends before two newlines)
# second is a list of parameter descriptions
# (other part of the string, one parameter description per line, starting with :param param_name:)
def doc_parser(doc):
    doc_parsed = doc.splitlines()
    return doc_parsed[1], doc_parsed[3:-1]


def print_entry(entryname, entry):
    if type(entry) in [list, set, types.GeneratorType]:
        i = 0
        simple_entries = []
        for v in entry:
            entry_str = print_entry(f"{entryname}.{i}", v)
            i += 1
            if entry_str:
                simple_entries.append(entry_str)
        if simple_entries:
            print(f"{entryname}: {'; '.join([str(v) for v in simple_entries])}")
    elif type(entry) is dict:
        for k in entry:
            entry_str = print_entry(f"{entryname}.{k}", entry[k])
            if entry_str:
                print(f"{entryname}.{k}: {entry_str}")
    else:
        return entry


if __name__ == "__main__":
    main()
