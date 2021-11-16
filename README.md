# BloodyAD Framework
BloodyAD is an Active Directory Privilege Escalation Framework, it can be used manually using `bloodyAD.py` or automatically by combining `pathgen.py` and `autobloody.py`.

This framework supports NTLM (with password or NTLM hashes) and Kerberos authentication and binds to LDAP/LDAPS/SAMR services of a domain controller to obtain AD privesc.

It is designed to be used transparently with a SOCKS proxy.

## bloodyAD
### Description
This tool can perform specific LDAP/SAMR calls to a domain controller in order to perform AD privesc.

### Requirements
The following are required:
- Python 3
- DSinternals
- Impacket
- Ldap3

### Usage
Simple usage:
```
python bloodyAD.py --host 172.16.1.15 -d MYDOM -u myuser -p :70016778cb0524c799ac25b439bd6a31 changePassword mytarget 'Password123!'
```

List of all available functions:
```
[bloodyAD]$ python bloodyAD.py -h
usage: bloodyAD.py [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-k] [-s {ldap,ldaps,rpc}] [--host HOST] {getGroupMembers,
getObjectAttributes, getObjectSID, addUser, addComputer, delObject, changePassword, addObjectToGroup, addForeignObjectToGroup,
delObjectFromGroup, getObjectsInOu, getOusInOu, getUsersInOu, getComputersInOu, addDomainSync, delDomainSync, addRbcd, delRbcd,
addShadowCredentials, delShadowCredentials, modifyGpoACL, setDontReqPreauthFlag, setAccountDisableFlag}
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
  {getGroupMembers, getObjectAttributes, getObjectSID, addUser, addComputer, delObject, changePassword, addObjectToGroup,
  addForeignObjectToGroup, delObjectFromGroup, getObjectsInOu, getOusInOu, getUsersInOu, getComputersInOu, addDomainSync,
  delDomainSync, addRbcd, delRbcd, addShadowCredentials, delShadowCredentials, modifyGpoACL, setDontReqPreauthFlag,
  setAccountDisableFlag}   Function to call
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

### How it works
bloodyAD communicates with a DC using mainly the LDAP protocol in order to get information or add/modify/delete AD objects. A password cannot be updated with LDAP, it must be a secure connection that is LDAPS or SAMR. A DC doesn't have LDAPS activated by default because it must be configured (with a certificate) so SAMR is used in those cases.

## autobloody
### Description
This tool automate the AD privesc between two AD objects, the source (the one we own) and the target (the one we want) if a privesc path exists.
The automation is split in two parts:
- `pathgen.py` to find the optimal path for privesc using bloodhound data and neo4j queries.
- `autobloody.py` to execute the path found with `pathgen.py`

### Requirements
The following are required:
- Python 3
- DSinternals
- Impacket
- Ldap3
- BloodHound
- Neo4j python driver
- Neo4j with the [GDS library](https://neo4j.com/docs/graph-data-science/current/installation/)

### How to use it
First data must be imported into BloodHound (e.g using SharpHound or BloodHound.py) and Neo4j must be running.

Simple usage:
```
pathgen.py -dp neo4jPass -ds 'OWNED_USER@ATTACK.LOCAL' -dt 'TARGET_USER@ATTACK.LOCAL' && autobloody.py -d ATTACK -u 'owned_user' -p 'owned_user_pass' --host 172.16.1.15
```

Full help for `pathgen.py`:
```
$ python pathgen.py -h
usage: pathgen.py [-h] [--dburi DBURI] [-du DBUSER] -dp DBPASSWORD -ds DBSOURCE -dt DBTARGET [-f FILEPATH]

Active Directory Privilege Escalation Framework

optional arguments:
  -h, --help            show this help message and exit
  --dburi DBURI         The host neo4j is running on. Default: localhost.
  -du DBUSER, --dbuser DBUSER
                        Neo4j username to use
  -dp DBPASSWORD, --dbpassword DBPASSWORD
                        Neo4j password to use
  -ds DBSOURCE, --dbsource DBSOURCE
                        Label of the source node
  -dt DBTARGET, --dbtarget DBTARGET
                        Label of the target node
  -f FILEPATH, --filepath FILEPATH
                        File path for the graph path file (default is path.json)
```

Full help for `autobloody.py`:
```
$ python autobloody.py -h
usage: autobloody.py [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-k] [-s {ldap,ldaps,rpc}] --host HOST [--path PATH]

Active Directory Privilege Escalation Framework

optional arguments:
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
  --path PATH           Path file (to generate with pathgen.py)

```

### How it works
First `pathgen.py` generates a privesc path using the Dijkstra's algorithm implemented into the Neo4j's GDS library.
The Dijkstra's algorithm allows to solve the shortest path problem on a weighted graph. By default the edges created by bloodhound don't have weight but a type (e.g MemberOf, WriteOwner). A weight is then added to each edge accordingly to the type of the edge and the type of the node reached (e.g user,group,domain).

Once a path is generated and stored as a json file, `autobloody.py` will connect to the DC and execute the path and clean what is reversible (everything except password change).