import dataclasses
from dataclasses import dataclass
from bloodyAD.network.ldap import Ldap
import os, socket


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
    format: str = ""
    dcip: str = ""
    krb_args: list = None
    kdc: str = ""
    kdcc: str = ""
    realmc: str = ""
    krbformat: str = "ccache"
    dns: str = ""
    timeout: int = 0

    def __post_init__(self):
        # Resolve dc ip
        if not self.dcip:
            try:
                self.dcip = socket.gethostbyname(self.host)
            except socket.gaierror as e:
                if e.errno == -5:
                    raise socket.gaierror(
                        "Can't resolve hostname provided in --host"
                    ) from e
                else:
                    raise

        # Parse krb args
        if self.krb_args is not None:
            self.kerberos = True
            for arg in self.krb_args:
                key, value = arg.split("=")
                if key == "kdc":
                    self.kdc = value
                elif key == "kdcc":
                    self.kdcc = value
                elif key == "realmc":
                    self.realmc = value
                elif key in ["ccache", "kirbi", "keytab"]:
                    self.key = value
                    self.krbformat = key
                else:
                    raise ValueError(f"{key} is not recognized as arg for --kerberos")

            if not (self.key or self.password or self.certificate):
                self.key = os.getenv("KRB5CCNAME")

            # If we have a kdc provided and user domain is different from dc domain we provide cross realm parameters
            if self.kdc and self.domain not in self.host:
                # If cross realm and no kdcc we consider it's the dc
                if not self.kdcc:
                    self.kdcc = self.dcip
                # If cross realm and no realmc we consider it's the host suffix
                if not self.realmc:
                    self.realmc = self.host.split(".", 1)[1]
            # If kdc hasn't been set we consider the ldap dc provided as kdc
            if not self.kdc:
                self.kdc = self.dcip

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
        if self.certificate and isinstance(self.certificate, str):
            if ":" in self.certificate:
                self.key, self.crt = self.certificate.split(":")
            else:
                self.crt = self.certificate

class ConnectionHandler:
    _ldap = None

    def __init__(self, args=None, config=None):
        if args:
            scheme = "ldap"
            if args.gc:
                scheme = "gc"
            elif args.secure:
                scheme = "ldaps"
            cnf = Config(
                domain=args.domain,
                username=args.username,
                password=args.password,
                scheme=scheme,
                host=args.host,
                krb_args=args.kerberos,
                certificate=args.certificate,
                dcip=args.dc_ip,
                format=args.format,
                dns=args.dns,
                timeout=args.timeout,
            )
        else:
            cnf = config
        self.conf = cnf

    @property
    def ldap(self):
        if not self._ldap:
            self._ldap = Ldap(self)
        elif not self._ldap.isactive:
            self._ldap = Ldap(self)
        return self._ldap

    def closeLdap(self):
        if not self._ldap:
            return
        self._ldap.close()
        self._ldap = None

    def rebind(self):
        self._ldap.close()
        self._ldap = Ldap(self)

    def switchUser(self, username, password):
        self.conf.username = username
        self.conf.password = password
        self.rebind()

    # kwargs takes the same arguments as the Config Class
    def copy(self, **kwargs):
        # If it's krb creds and the new host hasn't the same REALM as the previous connection we'll have to request a ticket for the new REALM from the previous kdcc if there is one, if not from the previous dc ip possible
        if (
            self.conf.kerberos
            and kwargs.get("host")
            and self.conf.domain not in kwargs.get("host")
        ):
            kirbi_tgt = self.ldap._con.auth.selected_authentication_context.kc.ccache.get_all_tgt_kirbis()[
                0
            ]
            kwargs["key"] = kirbi_tgt.to_b64()
            kwargs["krbformat"] = "kirbi"
            kwargs["format"] = "b64"
            if self.conf.kdcc:
                kwargs["kdc"] = self.conf.kdcc
            else:
                kwargs["kdc"] = self.conf.dcip
            # Reset previous conf params
            kwargs["krb_args"] = []
            kwargs["password"] = ""
            kwargs["kdcc"] = ""
            kwargs["realmc"] = ""
            if "dcip" not in kwargs:
                kwargs["dcip"] = ""

        newconf = dataclasses.replace(self.conf, **kwargs)
        return ConnectionHandler(config=newconf)
