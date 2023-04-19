# Enumeration with BloodyAD

## Get AD forest level
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get object 'DC=crash,DC=lab' --attr msDS-Behavior-Version

msDS-Behavior-Version: DS_BEHAVIOR_WIN2016
```

## Get Machine Account Quota (MAQ)
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get object 'DC=crash,DC=lab' --attr ms-DS-MachineAccountQuota                     

ms-DS-MachineAccountQuota: 10
```

## Get min Password Length
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get object 'DC=crash,DC=lab' --attr minPwdLength

minPwdLength: 7
```

## Get all users
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get children 'DC=crash,DC=lab' --type user

distinguishedName: CN=Administrator,CN=Users,DC=crash,DC=lab

distinguishedName: CN=Guest,CN=Users,DC=crash,DC=lab
[...]
```

## Get all computers
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get children 'DC=crash,DC=lab' --type computer

distinguishedName: CN=DC,OU=Domain Controllers,DC=crash,DC=lab

distinguishedName: CN=SQL01,CN=Computers,DC=crash,DC=lab

distinguishedName: CN=ADCS,CN=Computers,DC=crash,DC=lab
```

## Get all containers
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get children 'DC=crash,DC=lab' --type container

distinguishedName: CN=Users,DC=crash,DC=lab     

distinguishedName: CN=Computers,DC=crash,DC=lab    

distinguishedName: CN=System,DC=crash,DC=lab    

distinguishedName: CN=ForeignSecurityPrincipals,DC=crash,DC=lab
[...]
```


## Get Kerberoastable accounts
```
python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search 'DC=crash,DC=lab' --filter '(&(samAccountType=805306368)(servicePrincipalName=*))' --attr sAMAccountName | grep sAMAccountName | cut -d ' ' -f 2

krbtgt
iis_user
```

## Get accounts that do not require Kerberos pre-authentication (AS-REP)
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search 'DC=crash,DC=lab' --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName  

distinguishedName: CN=Unix,CN=Users,DC=crash,DC=lab
sAMAccountName: unix
```

## Get all DNS record from AD
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get dnsDump --detail

domain: _msdcs.crash.lab
NS: dc.crash.lab
SOA: dc.crash.lab
SOA: hostmaster@crash.lab

domain: _kerberos._tcp.dc._msdcs.crash.lab
SRV: dc.crash.lab:88

domain: _kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.crash.lab
SRV: dc.crash.lab:88

domain: _ldap._tcp.886e9d3a-c7e3-4d01-95ad-ee3a2ee19e8f.domains._msdcs.crash.lab
SRV: dc.crash.lab:389
[...]
```


## Check if ADIDNS has a wildcard entry (if not, check ADIDNS spoofing)
```
> python bloodyAD.py -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get dnsDump | sed -n '/[^\n]*\*/,/^$/p'

domain: *.crash.lab
A: 10.100.10.2
```


