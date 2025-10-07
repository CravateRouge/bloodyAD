import logging, sys

LOG = logging.getLogger('bloodyAD')

def enableCliLogger(level="DEBUG"):
    # If we want to get the logs of every library we used (and which properly defined their loggers)
    if level == "TRACE":
        # logging.basicConfig(
        #         level=logging.DEBUG,
        #         #format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        #     )
        logging.getLogger().setLevel(logging.DEBUG)
        level = "DEBUG"
    LOG.propagate = False
    LOG.setLevel("DEBUG")
    handler = logging.StreamHandler(sys.stdout)
    class SymbolFormatter(logging.Formatter):
        LEVEL_SYMBOLS = {
            logging.DEBUG: '[*]',
            logging.INFO: '[+]',
            logging.WARNING: '[!]',
            logging.ERROR: '[-]',
            logging.CRITICAL: '[X]',
        }
        def format(self, record):
            symbol = self.LEVEL_SYMBOLS.get(record.levelno, '[?]')
            return f"{symbol} {record.getMessage()}"
    handler.setFormatter(SymbolFormatter())
    handler.setLevel(getattr(logging, level))
    LOG.addHandler(handler)

class BloodyError(Exception):
    pass


class LDAPError(BloodyError):
    pass


class ResultError(LDAPError):
    def __init__(self, result):
        self.result = result

        if self.result["result"] == 50:
            self.message = (
                "Could not modify object, the server reports insufficient rights: "
                + self.result["message"]
            )
        elif self.result["result"] == 19:
            self.message = (
                "Could not modify object, the server reports a constrained"
                " violation: " + self.result["message"]
            )
        else:
            self.message = "The server returned an error: " + self.result["message"]

        super().__init__(self.message)


class NoResultError(LDAPError):
    def __init__(self, search_base, ldap_filter):
        self.filter = ldap_filter
        self.base = search_base
        self.message = f"No object found in {self.base} with filter: {self.filter}"
        super().__init__(self.message)


class TooManyResultsError(LDAPError):
    def __init__(self, search_base, ldap_filter, entries):
        self.filter = ldap_filter
        self.base = search_base
        self.limit = 10
        self.entries = list(entries)

        if len(self.entries) <= self.limit:
            self.results = "\n".join(entry["dn"] for entry in entries)
            self.message = (
                f"{len(self.entries)} objects found in {self.base} with"
                f" filter: {ldap_filter}\n"
            )
            self.message += "\tPlease put the full target DN\n"
            self.message += f"\tResult of query: \n{self.results}"
        else:
            self.message = (
                f"\tMore than {self.limit} entries in {self.base} match {self.filter}"
            )
            self.message += "\tPlease put the full target DN"

        super().__init__(self.message)
