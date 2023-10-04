from dataclasses import dataclass
from bloodyAD.network.ldap import Ldap


@dataclass
class Config:
    """Class for keeping all connection data for domain"""

    scheme: str = "ldap"
    host: str = ""
    domain: str = ""
    username: str = ""
    password: str = ""
    lmhash: str = "aad3b435b51404eeaad3b435b51404ee"
    nthash: str = ""
    kerberos: bool = False
    certificate: str = ""
    crt: str = ""
    key: str = ""
    url: str = ""

    def __post_init__(self):
        # Handle case where password is hashes
        if self.password and ":" in self.password:
            lmhash_maybe, nthash_maybe = self.password.split(":")
            try:
                int(nthash_maybe, 16)
            except ValueError:
                self.lmhash, self.nthash = None, None
            else:
                if len(lmhash_maybe) == 0 and len(nthash_maybe) == 32:
                    self.nthash = nthash_maybe
                    self.password = f"{self.lmhash}:{self.nthash}"
                elif len(lmhash_maybe) == 32 and len(nthash_maybe) == 32:
                    self.lmhash = lmhash_maybe
                    self.nthash = nthash_maybe
                    self.password = f"{self.lmhash}:{self.nthash}"
                else:
                    self.lmhash, self.nthash = None, None

        # Handle case where certificate is provided
        if self.certificate:
            self.key, self.crt = self.certificate.split(":")

        # Build the url from parameters given
        self.url = self.scheme + "://" + self.host


class ConnectionHandler:
    _ldap = None

    def __init__(self, args=None, config=None):
        if args:
            scheme = "ldaps" if args.secure else "ldap"
            cnf = Config(
                domain=args.domain,
                username=args.username,
                password=args.password,
                scheme=scheme,
                host=args.host,
                kerberos=args.kerberos,
                certificate=args.certificate,
            )
        else:
            cnf = config
        self.conf = cnf

    @property
    def ldap(self):
        if not self._ldap:
            self._ldap = Ldap(self.conf)
        return self._ldap

    def rebind(self):
        self._ldap.unbind()
        self._ldap = Ldap(self.conf)

    def switchUser(self, username, password):
        self.conf.username = username
        self.conf.password = password
        self.rebind()
