# bloodyAD
BloodyAD is an Active Directory Privilege Escalation Framework.

## Description
This tool can perform specific LDAP/SAMR calls to a domain controller in order to perform AD privesc.
It supports authentication using password, NTLM hashes or Kerberos.

## Requirements
The following are required:
- Python 3
- DSinternals
- Impacket
- Ldap3

## Usage
Simple usage:
```
python bloodyAD.py --host 172.16.1.15 -d MYDOM -u myuser -p :70016778cb0524c799ac25b439bd6a31 changePassword mytarget 'Password123!'
```

List of all available functions:
```
[bloodyAD]$ python bloodyAD.py -h
usage: bloodyAD.py [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-k] [-s {ldap,ldaps,rpc}] [--host HOST] {getGroupMembers, getObjectAttributes, getObjectSID, addUser, addComputer, delObject, changePassword, addObjectToGroup, addForeignObjectToGroup, delObjectFromGroup, getObjectsInOu, getOusInOu, getUsersInOu, getComputersInOu, addDomainSync, delDomainSync, addRbcd, delRbcd, addShadowCredentials, delShadowCredentials, modifyGpoACL, setDontReqPreauthFlag, setAccountDisableFlag}
                          ...

Active Directory Privilege Escalation Framework

Main options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain used for NTLM authentication
  -u USERNAME, --username USERNAME
                        Username used for NTLM authentication
  -p PASSWORD, --password PASSWORD
                        Cleartext password or LMHASH:NTHASH for NTLM authentication
  -k, --kerberos
  -s {ldap,ldaps,rpc}, --scheme {ldap,ldaps,rpc}
                        Use LDAP over TLS (default is LDAP)
  --host HOST           Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)

Commands:
  {getGroupMembers, getObjectAttributes, getObjectSID, addUser, addComputer, delObject, changePassword, addObjectToGroup, addForeignObjectToGroup, delObjectFromGroup, getObjectsInOu, getOusInOu, getUsersInOu, getComputersInOu, addDomainSync, delDomainSync, addRbcd, delRbcd, addShadowCredentials, delShadowCredentials, modifyGpoACL, setDontReqPreauthFlag, setAccountDisableFlag}   Function to call
```

Help text to use a specific function:
```
[bloodyAD]$ python bloodyAD.py --host 172.16.1.15 -d MYDOM -u myuser -p :70016778cb0524c799ac25b439bd6a31 changePassword -h
usage: 
    Change the target password without knowing the old one using LDAPS or RPC
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        new_pass: new password for the target
    
       [-h] [func_args ...]

positional arguments:
  func_args

optional arguments:
  -h, --help  show this help message and exit
  ```
  
## How it works
bloodyAD communicates with a DC using mainly the LDAP protocol in order to get information or add/modify/delete AD objects. A password cannot be updated with LDAP, it must be a secure connection that is LDAPS or SAMR. A DC doesn't have LDAPS activated by default because it must be configured (with a certificate) so SAMR is used in those cases.
