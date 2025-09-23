#!/usr/bin/env python3
from bloodyAD import cli_modules, ConnectionHandler, exceptions
import sys, argparse, types, logging, json

# For dynamic argparse
import inspect, pkgutil, importlib


def main():
    parser = argparse.ArgumentParser(description="AD Privesc Swiss Army Knife")

    parser.add_argument("-d", "--domain", help="Domain used for NTLM authentication")
    parser.add_argument(
        "-u", "--username", help="Username used for NTLM authentication"
    )
    parser.add_argument(
        "-p",
        "--password",
        help=(
            "password or LMHASH:NTHASH for NTLM authentication, password or AES/RC4 key for kerberos, password for certificate"
            " (Do not specify to trigger integrated windows authentication)"
        ),
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        nargs="*",
        help=(
            "Enable Kerberos authentication. If '-p' is provided it will try to query a TGT with it. You can also provide a list of one or more optional keywords as '-k kdc=192.168.100.1 kdcc=192.168.150.1 realmc=foreign.realm.corp <keyfile_type>=/home/silver/Admin.ccache', <keyfile_type> being ccache, kirbi or keytab, 'kdc' being the kerberos server for the keyfile provided and 'realmc' and 'kdcc' for cross realm (the realm of the '--host' provided)"
        ),
    )
    parser.add_argument(
        "-f",
        "--format",
        help="Specify format for '--password' or '-k <keyfile>'",
        choices=["b64", "hex", "aes", "rc4", "default"],
        default="default",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        nargs="?",
        help='Schannel authentication or krb pkinit if -k also provided, e.g: "path/to/key:path/to/cert" (Use Windows Certstore with krb if left empty)',
    )
    parser.add_argument(
        "-s",
        "--secure",
        help="Try to use LDAP/GC over TLS aka LDAPS/GCS (default is no TLS)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--host",
        help="Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)",
        required=True
    )
    parser.add_argument(
        "--dc-ip",
        help="IP of the DC (useful if you provided a --host which can't resolve)",
    )
    parser.add_argument(
        "--dns",
        help="IP of the DNS to resolve AD names (useful for inter-domain functions)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Connection timeout in seconds",
    )
    parser.add_argument(
        "--gc",
        help="Connect to Global Catalog (GC)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Adjust output verbosity",
        choices=["QUIET", "INFO", "DEBUG"],
        default="INFO",
    )
    parser.add_argument(
        "--json",
        help="Output results in JSON format",
        action="store_true",
        default=False,
    )

    subparsers = parser.add_subparsers(title="Commands")
    submodnames = []
    # Iterates all submodules in module package and creates one parser per submodule
    for importer, submodname, ispkg in pkgutil.iter_modules(cli_modules.__path__):
        submodnames.append(submodname)
        subparser = subparsers.add_parser(
            submodname, help=f"[{submodname.upper()}] function category"
        )
        subsubparsers = subparser.add_subparsers(title=f"{submodname} commands")
        submodule = importlib.import_module("." + submodname, cli_modules.__name__)
        for function_name, function in inspect.getmembers(
            submodule, inspect.isfunction
        ):
            function_doc, params_doc = doc_parser(inspect.getdoc(function))
            # This formatter class prints default values
            subsubparser = subsubparsers.add_parser(
                function_name,
                help=function_doc,
                formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            )
            # Gets function signature to extract parameters default values
            func_signature = inspect.signature(function)
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

    # Preprocess the input arguments because nargs ? and * can capture subparsers commands if put at the end
    # So we always put the --host option at the end
    input_args = sys.argv[1:]
    isHost = False
    parsed_args = []
    host_arg = None
    for arg in input_args:
        if arg == "--host":
            isHost = True
        elif isHost:
            isHost = False
            host_arg = arg
        elif arg in submodnames:
            parsed_args.append("--host")
            parsed_args.append(host_arg)
            parsed_args.append(arg)
        else:
            parsed_args.append(arg)
    args = parser.parse_args(parsed_args)

    if "func" not in args:
        parser.print_help(sys.stderr)
        sys.exit(1)
    # Get the list of parameters to provide to the command
    param_names = args.func.__code__.co_varnames[1 : args.func.__code__.co_argcount]
    params = {param_name: vars(args)[param_name] for param_name in param_names}

    # Configure loggers #

    # Doesn't work when launching new threads in bloodyAD.ldap so we'll use propagate to false below
    # # Enable all children loggers in debug mode
    # logging.getLogger().setLevel(logging.DEBUG)
    # # Make the root logger quiet
    # # WARNING: operation below is not thread safe!
    # logging.getLogger().handlers = []

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    exceptions.LOG.addHandler(handler)
    exceptions.LOG.setLevel(getattr(logging, args.verbose))
    exceptions.LOG.propagate = False
    # We show badldap logs only if debug is enabled
    # import badldap
    # if args.verbose == "DEBUG":
    #     badldap.logger.handlers = []
    #     handler = logging.StreamHandler(sys.stdout)
    #     handler.setLevel(logging.DEBUG)
    #     formatter = logging.Formatter('[badldap] %(message)s')
    #     handler.setFormatter(formatter)
    #     badldap.logger.addHandler(handler)
    #     badldap.logger.setLevel(logging.DEBUG)
    #     badldap.logger.propagate = False

    # Launch the command
    conn = ConnectionHandler(args=args)
    try:
        output = args.func(conn, **params)

        # Prints output, will print it directly if it's not an iterable
        # Output is expected to be of type [{name:[members]},{...}...]
        # If it's not, will print it raw
        output_type = type(output)
        if not output or output_type == bool:
            return

        if output_type not in [list, dict, types.GeneratorType]:
            if args.json:
                print(json.dumps({"result": str(output)}, indent=2))
            else:
                print("\n" + output)
            return

        # Collect all entries for JSON output
        if args.json:
            json_results = []
            for entry in output:
                json_results.append(json_serialize_entry(entry))
            
            # If only one result, output it directly without array wrapper
            if len(json_results) == 1:
                print(json.dumps(json_results[0], indent=2))
            else:
                print(json.dumps(json_results, indent=2))
        else:
            # Original human-readable output
            for entry in output:
                print()
                for attr_name, attr_val in entry.items():
                    entry_str = print_entry(attr_name, attr_val)
                    if not (entry_str is None or entry_str == ""):
                        print(f"{attr_name}: {entry_str}")

    # Close the connection properly anyway
    finally:
        conn.closeLdap()


# Gets unparsed doc and returns a tuple of two values
# first is function description (starts at the beginning of the string and ends before two newlines)
# second is a list of parameter descriptions
# (other part of the string, one parameter description per line, starting with :param param_name:)
def doc_parser(doc):
    doc_parsed = doc.splitlines()
    return doc_parsed[0], doc_parsed[2:]


def json_serialize_entry(entry):
    """
    Convert an entry to JSON-serializable format by converting custom objects to strings
    """
    if isinstance(entry, dict):
        return {k: json_serialize_entry(v) for k, v in entry.items()}
    elif isinstance(entry, (list, set, types.GeneratorType)):
        return [json_serialize_entry(v) for v in entry]
    else:
        # Convert custom objects to string representation
        return str(entry)


def print_entry(entryname, entry):
    if type(entry) in [list, set, types.GeneratorType]:
        i = 0
        simple_entries = []
        length = len(entry)
        i_str = ""
        for v in entry:
            if length > 1:
                i_str = f".{i}"
            entry_str = print_entry(f"{entryname}{i_str}", v)
            i += 1
            if not (entry_str is None or entry_str == ""):
                simple_entries.append(entry_str)
        if simple_entries:
            print(f"{entryname}: {'; '.join([str(v) for v in simple_entries])}")
    elif type(entry) is dict:
        length = len(entry)
        k_str = ""
        for k in entry:
            if length > 1:
                k_str = f".{k}"
            entry_str = print_entry(f"{entryname}{k_str}", entry[k])
            if not (entry_str is None or entry_str == ""):
                print(f"{entryname}.{k}: {entry_str}")
    else:
        return entry


if __name__ == "__main__":
    main()
