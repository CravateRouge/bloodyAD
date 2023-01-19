# Enumeration with BloodyAD

## Get AD forest level
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getObjectAttributes 'DC=crash,DC=lab' msDS-Behavior-Version
{
    "msDS-Behavior-Version": "DS_BEHAVIOR_WIN2016"
}
```

## Get Machine Account Quota (MAQ)
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getObjectAttributes 'DC=crash,DC=lab' ms-DS-MachineAccountQuota                     
{
    "ms-DS-MachineAccountQuota": 10
}
```

## Get min Password Length
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getObjectAttributes 'DC=crash,DC=lab' minPwdLength

{
    "minPwdLength": 7
}

```

## Get all users
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getChildObjects 'DC=crash,DC=lab' user

[
    "CN=Administrator,CN=Users,DC=crash,DC=lab",
    "CN=Guest,CN=Users,DC=crash,DC=lab",
    [...]
]
```

## Get all computers
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getChildObjects 'DC=crash,DC=lab' computer

[
    "CN=DC,OU=Domain Controllers,DC=crash,DC=lab",
    "CN=SQL01,CN=Computers,DC=crash,DC=lab",
    "CN=ADCS,CN=Computers,DC=crash,DC=lab"
]
```

## Get all containers
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 getChildObjects 'DC=crash,DC=lab' container
                                                                                                                       
[                                                                                                                      
    "CN=Users,DC=crash,DC=lab",                                                                                        
    "CN=Computers,DC=crash,DC=lab",                                                                                    
    "CN=System,DC=crash,DC=lab",                                                                                       
    "CN=ForeignSecurityPrincipals,DC=crash,DC=lab",
    [...]
]
```


## Get Kerberoastable accounts
```
python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 search 'DC=crash,DC=lab' '(&(samAccountType=805306368)(servicePrincipalName=*))' sAMAccountName | jq -r '.entries[].attributes.sAMAccountName'

krbtgt
iis_user
```

## Get accounts that do not require Kerberos pre-authentication (AS-REP)
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 search 'DC=crash,DC=lab' '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' sAMAccountName  

{
    "entries": [
        {
            "attributes": {
                "sAMAccountName": "unix"
            },
            "dn": "CN=Unix,CN=Users,DC=crash,DC=lab"
        }
    ]
}
```

## Get all DNS record from AD
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get domainDNSRecord

_msdcs.crash.lab. :-> dc.crash.lab. :-> NS
_msdcs.crash.lab. :-> dc.crash.lab. :-> hostmaster.crash.lab. :-> SOA
_kerberos._tcp.dc._msdcs.crash.lab. :-> dc.crash.lab.:88 :-> SRV
_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.crash.lab. :-> dc.crash.lab.:88 :-> SRV
_ldap._tcp.886e9d3a-c7e3-4d01-95ad-ee3a2ee19e8f.domains._msdcs.crash.lab. :-> dc.crash.lab.:389 :-> SRV
[...]
```


## Check if ADIDNS has a wildcard entry (if not, check ADIDNS spoofing)
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get domainDNSRecord | grep '*'

*.crash.lab. :-> 10.100.10.2 :-> A
```


