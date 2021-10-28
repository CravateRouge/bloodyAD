import ldap3
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5 import rpcrt
from dataclasses import dataclass


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
    url: str = ""

    def __post_init__(self):
        lmhash_maybe, nthash_maybe = self.password.split(':')

        try:
            int(nthash_maybe, 16)
        except ValueError:
            self.lmhash, self.nthash = None, None
        else:
            if len(lmhash_maybe) == 0 and len(nthash_maybe) == 32:
                self.lmhash = "aad3b435b51404eeaad3b435b51404ee"
                self.nthash = nthash_maybe
            elif len(lmhash_maybe) == 32 and len(nthash_maybe) == 32:
                self.lmhash = lmhash_maybe
                self.nthash = nthash_maybe
            else:
                self.lmhash, self.nthash = None, None

        self.url = self.scheme + '://' + self.host


class ConnectionHandler():
    def __init__(self, args):
        cnf = Config(domain=args.domain, username=args.username,
                     password=args.password, scheme=args.scheme, host=args.host,
                     kerberos=args.kerberos)
        self.conf = cnf
        self.samr = None
        self.ldap = None

    def getSamrConnection(self):
        if not self.samr:
            self.samr = self._connectSamr()
        return self.samr

    def _connectSamr(self):
        cnf = self.conf
        rpctransport = transport.SMBTransport(cnf.host, filename=r'\samr')
        rpctransport.set_credentials(cnf.username, cnf.password, cnf.domain,
                                     lmhash=cnf.lmhash, nthash=cnf.nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    def getLdapConnection(self):
        if not self.ldap:
            self.ldap = self._connectLDAP()
        return self.ldap

    def _connectLDAP(self):
        cnf = self.conf
        s = ldap3.Server(cnf.url, get_info=ldap3.DSA)

        if cnf.kerberos:
            c = ldap3.Connection(s, authentication=ldap3.SASL,
                                 sasl_mechanism=ldap3.KERBEROS,
                                 sasl_credentials=(ldap3.ReverseDnsSetting.REQUIRE_RESOLVE_ALL_ADDRESSES,))
        else:
            c = ldap3.Connection(s, user='%s\\%s' % (cnf.domain, cnf.username),
                                 password=cnf.password, authentication=ldap3.NTLM)

        c.bind()
        return c
