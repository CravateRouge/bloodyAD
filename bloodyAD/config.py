from dataclasses import dataclass


@dataclass
class Config:
    """Class for keeping all connection data for domain"""
    scheme: str = "ldap"
    host: str = ""
    domain: str = ""
    username: str = ""
    password: str = ""
    lm_hash: str = "aad3b435b51404eeaad3b435b51404ee"
    nt_hash: str = ""
    kerberos: bool = False

    def __post_init__(self):
        lmhash_maybe, nthash_maybe = self.password.split(':')

        try:
            int(nthash_maybe, 16)
        except ValueError:
            self.lmhash, self.nthash = None, None
        else:
            if len(lmhash_maybe) == 0 and len(nthash_maybe) == 32:
                self.lm_hash = "aad3b435b51404eeaad3b435b51404ee"
                self.nt_hash = nthash_maybe
            elif len(lmhash_maybe) == 32 and len(nthash_maybe) == 32:
                self.lm_hash = lmhash_maybe
                self.nt_hash = nthash_maybe
            else:
                self.lmhash, self.nthash = None, None

        
cnf = None
