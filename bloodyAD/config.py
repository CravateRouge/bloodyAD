import ldap3
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5 import rpcrt
from dataclasses import dataclass

from .formatters import formatSD

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

        # Handle case where password is hashes
        if ':' in self.password:
            lmhash_maybe, nthash_maybe = self.password.split(':')
            try:
                int(nthash_maybe, 16)
            except ValueError:
                self.lmhash, self.nthash = None, None
            else:
                if len(lmhash_maybe) == 0 and len(nthash_maybe) == 32:
                    self.nthash = nthash_maybe
                    self.password = f'{self.lmhash}:{self.nthash}'
                elif len(lmhash_maybe) == 32 and len(nthash_maybe) == 32:
                    self.lmhash = lmhash_maybe
                    self.nthash = nthash_maybe
                    self.password = f'{self.lmhash}:{self.nthash}'
                else:
                    self.lmhash, self.nthash = None, None

        # Build the url from parameters given
        self.url = self.scheme + '://' + self.host


class ConnectionHandler():
    def __init__(self, args=None, config=None):
        if args:
            cnf = Config(domain=args.domain, username=args.username, password=args.password, scheme=args.scheme, host=args.host, kerberos=args.kerberos)
        else:
            cnf = config

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

        if cnf.nthash:
            rpctransport.set_credentials(cnf.username, cnf.password, cnf.domain,
                                        lmhash=cnf.lmhash, nthash=cnf.nthash)
        else:
            rpctransport.set_credentials(cnf.username, cnf.password, cnf.domain)

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
        s = ldap3.Server(cnf.url, get_info=ldap3.ALL,formatter={'nTSecurityDescriptor':formatSD, 'msDS-AllowedToActOnBehalfOfOtherIdentity':formatSD})

        if cnf.kerberos:
            c = ldap3.Connection(s, authentication=ldap3.SASL,
                                 sasl_mechanism=ldap3.KERBEROS,
                                 sasl_credentials=(ldap3.ReverseDnsSetting.REQUIRE_RESOLVE_ALL_ADDRESSES,), raise_exceptions=True)
        else:
            c = ldap3.Connection(s, user='%s\\%s' % (cnf.domain, cnf.username),
                                 password=cnf.password, authentication=ldap3.NTLM, raise_exceptions=True)

        c.bind()
        return c
    
    def close(self):
        self._closeSamr()
        self._closeLdap()
        
    def _closeSamr(self):
        if self.samr:
            self.samr.disconnect()
            self.samr = None
    
    def _closeLdap(self):
        if self.ldap:
            self.ldap.unbind()
            self.ldap = None

    def switchUser(self, username, password):
        self.conf.username = username
        self.conf.password = password
        if self.ldap:
            self.ldap.rebind(user='%s\\%s' % (self.conf.domain, username), password=password, authentication=ldap3.NTLM)
        self._closeSamr()

