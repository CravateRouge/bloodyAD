from bloodyAD import patch
from bloodyAD.formatters import formatters
from bloodyAD.formatters.formatters import (
    formatFunctionalLevel,
    formatGMSApass,
    formatSD,
    formatSchemaVersion,
    formatAccountControl,
    formatDnsRecord,
    formatKeyCredentialLink,
)
import ssl
from dataclasses import dataclass
import ldap3


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
        self.ldap = None

    def getLdapConnection(self):
        if not self.ldap:
            self.ldap = self._connectLDAP()
        return self.ldap

    def _connectLDAP(self):
        cnf = self.conf
        ldap_server_kwargs = {
            "host": cnf.url,
            "get_info": ldap3.ALL,
            "formatter": {
                "nTSecurityDescriptor": formatSD,
                "msDS-AllowedToActOnBehalfOfOtherIdentity": formatSD,
                "msDS-Behavior-Version": formatFunctionalLevel,
                "objectVersion": formatSchemaVersion,
                "userAccountControl": formatAccountControl,
                "msDS-ManagedPassword": formatGMSApass,
                "dnsRecord": formatDnsRecord,
                "msDS-KeyCredentialLink": formatKeyCredentialLink,
            },
        }
        ldap_connection_kwargs = {"raise_exceptions": True}

        if cnf.crt:
            key = cnf.key if cnf.key else None
            tls = ldap3.Tls(
                local_private_key_file=key,
                local_certificate_file=cnf.crt,
                validate=ssl.CERT_NONE,
            )
            ldap_server_kwargs["tls"] = tls
            if cnf.scheme != "ldaps":
                ldap_connection_kwargs.update(
                    {
                        "authentication": ldap3.SASL,
                        "sasl_mechanism": ldap3.EXTERNAL,
                        "auto_bind": ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                    }
                )
        elif cnf.kerberos:
            ldap_connection_kwargs.update(
                {
                    "authentication": ldap3.SASL,
                    "sasl_mechanism": ldap3.KERBEROS,
                }
            )
            if cnf.scheme != "ldaps":
                ldap_connection_kwargs.update({"session_security": "ENCRYPT"})

        else:
            ldap_connection_kwargs.update(
                {
                    "user": "%s\\%s" % (cnf.domain, cnf.username),
                    "password": cnf.password,
                    "authentication": ldap3.NTLM,
                }
            )
            if cnf.scheme != "ldaps":
                ldap_connection_kwargs.update({"session_security": "ENCRYPT"})

        s = ldap3.Server(**ldap_server_kwargs)
        c = ldap3.Connection(s, **ldap_connection_kwargs)
        if cnf.crt and cnf.scheme == "ldaps":
            c.open()
        else:
            c.bind()

        formatters.helpers.ldap_conn = c
        return c

    def close(self):
        self._closeLdap()

    def _closeLdap(self):
        if self.ldap:
            self.ldap.unbind()
            self.ldap = None

    def switchUser(self, username, password):
        self.conf.username = username
        self.conf.password = password
        self._closeLdap()
