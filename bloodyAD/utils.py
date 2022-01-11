import ldap3
import impacket
import logging
from ldap3.protocol.formatters.formatters import format_sid
from impacket.ldap import ldaptypes
from impacket.dcerpc.v5 import samr, dtypes

from .exceptions import NoResultError, ResultError, TooManyResultsError

LOG = logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(message)s')


# 983551 Full control
def createACE(sid, object_type=None, access_mask=983551):
    nace = ldaptypes.ACE()
    nace['AceFlags'] = 0x00

    if object_type is None:
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    else:   
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        acedata['ObjectType'] = impacket.uuid.string_to_bin(object_type)
        acedata['InheritedObjectType'] = b''
        acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT

    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = access_mask

    if type(sid) is str:
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
    else:
        acedata['Sid'] = sid

    nace['Ace'] = acedata
    return nace


def createEmptySD():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd


def resolvDN(conn, identity, objtype=None):
    """
    Return the DN for the object based on the parameters identity
    Args:
        identity: sAMAccountName, DN, GUID or SID of the user
        objtype: None is default or GPO
    """

    if "dc=" in identity.lower():
        # identity is a DN, return as is
        # We do not try to validate it because it could be from another trusted domain
        return identity

    if "s-1-" in identity.lower():
        # We assume identity is an SID
        ldap_filter = f'(objectSid={identity})'

    elif "{" in identity:
        if objtype == "GPO":
            ldap_filter = f'(&(objectClass=groupPolicyContainer)(name={identity}))'
        else:        
            # We assume identity is a GUID
            ldap_filter = f'(objectGUID={identity})'
    else:
        # By default, we assume identity is a sam account name
        ldap_filter = f'(sAMAccountName={identity})'

    naming_context = getDefaultNamingContext(conn)
    conn.search(naming_context, ldap_filter)

    entries = [e for e in conn.response if e.get('type', '') == 'searchResEntry']

    if len(entries) < 1:
        raise NoResultError(naming_context, ldap_filter)

    if len(entries) > 1:
        raise TooManyResultsError(naming_context, ldap_filter, entries)

    res = entries[0]['dn']
    return res


def getDefaultNamingContext(conn):
    naming_context = conn.server.info.other['defaultNamingContext'][0]
    return naming_context


def getObjectSID(conn, identity):
    """
    Get the SID for the given identity
    Args:
        identity: sAMAccountName, DN, GUID or SID of the object
    """
    ldap_conn = conn.getLdapConnection()
    object_dn = resolvDN(ldap_conn, identity)
    ldap_conn.search(object_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes='objectSid')
    object_sid = ldap_conn.response[0]['raw_attributes']['objectSid'][0]
    LOG.info(f'[+] {identity} SID is: {format_sid(object_sid)}')
    return object_sid


def cryptPassword(session_key, password):
    try:
        from Cryptodome.Cipher import ARC4
    except Exception:
        LOG.error("Warning: You don't have any crypto installed. You need pycryptodomex")
        LOG.error("See https://pypi.org/project/pycryptodomex/")

    sam_user_pass = samr.SAMPR_USER_PASSWORD()
    encoded_pass = password.encode('utf-16le')
    plen = len(encoded_pass)
    sam_user_pass['Buffer'] = b'A' * (512 - plen) + encoded_pass
    sam_user_pass['Length'] = plen
    pwdBuff = sam_user_pass.getData()

    rc4 = ARC4.new(session_key)
    encBuf = rc4.encrypt(pwdBuff)

    sam_user_pass_enc = samr.SAMPR_ENCRYPTED_USER_PASSWORD()
    sam_user_pass_enc['Buffer'] = encBuf
    return sam_user_pass_enc


def userAccountControl(conn, identity, enable, flag):
    enable = enable == "True"
    
    conn = conn.getLdapConnection()
    user_dn = resolvDN(conn, identity)
    conn.search(user_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes='userAccountControl')
    userAccountControl = conn.response[0]['attributes']['userAccountControl']
    LOG.debug(f"Original userAccountControl: {userAccountControl}")

    if enable:
        userAccountControl = userAccountControl | flag
    else:
        userAccountControl = userAccountControl & ~flag

    LOG.debug(f"Updated userAccountControl: {userAccountControl}")
    conn.modify(user_dn, {'userAccountControl': (ldap3.MODIFY_REPLACE, [userAccountControl])})

    if conn.result['result'] == 0:
        LOG.info("Updated userAccountControl attribute successfully")
    else:
        raise ResultError(conn.result)


def rpcChangePassword(conn, target, new_pass):
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
    dce = conn.getSamrConnection()
    server_handle = samr.hSamrConnect(dce, conn.conf.host + '\x00')['ServerHandle']
    domainSID = samr.hSamrLookupDomainInSamServer(dce, server_handle, conn.conf.domain)['DomainId']
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
    return resp

def modifySecDesc(conn, identity, target,
    ldap_filter='(objectClass=*)', ldap_attribute='nTSecurityDescriptor',
    object_type=None, access_mask=ldaptypes.ACCESS_MASK.GENERIC_ALL, control_flag=None, enable="True"):

    enable = enable == "True"
    ldap_conn = conn.getLdapConnection()

    target_dn = resolvDN(ldap_conn, target)
    controls=None
    if control_flag:
        controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=control_flag)
    ldap_conn.search(target_dn, ldap_filter, search_scope=ldap3.BASE, attributes=ldap_attribute, controls=controls)

    if len(ldap_conn.entries) < 1:
        raise NoResultError(target_dn, ldap_filter)

    entry_dn = ldap_conn.entries[0].entry_dn

    sd_data = ldap_conn.entries[0][ldap_attribute].raw_values
    if len(sd_data) < 1:
        sd = createEmptySD()
    else:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

    old_sd = sd
    user_sid = getObjectSID(conn, identity)
    attr_values = []

    if control_flag == dtypes.OWNER_SECURITY_INFORMATION:
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        sd['OwnerSid'].fromCanonical(format_sid(user_sid))
        attr_values.append(sd.getData())
    else:
        if enable:
            sd['Dacl'].aces.append(createACE(sid=user_sid, access_mask=access_mask))
        else:
            aces_to_keep = []
            LOG.debug('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                ace_sid = ace['Ace']['Sid']
                if ace_sid.getData() == user_sid:
                    LOG.debug('    %s (will be removed)' % ace_sid.formatCanonical())
                else:
                    LOG.debug('    %s' % ace_sid.formatCanonical())
                    aces_to_keep.append(ace)
                    sd['Dacl'].aces = aces_to_keep
        # Remove the attribute if there is no ace to keep
        if len(sd['Dacl'].aces) > 0 or ldap_attribute == 'nTSecurityDescriptor':
            attr_values.append(sd.getData())

    ldap_conn.modify(entry_dn, {ldap_attribute: [ldap3.MODIFY_REPLACE, attr_values]}, controls=controls)
    if ldap_conn.result['result'] == 0:
        return old_sd
    else:
        raise ResultError(ldap_conn.result)