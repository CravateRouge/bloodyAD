
import base64, binascii, uuid
from impacket.ldap import ldaptypes
from impacket.structure import Structure
from Cryptodome.Hash import MD4

ldap_conn = None


# https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
ACCESS_FLAGS = {
    # Flag constants
    'GENERIC_READ' : 0x80000000,
    'GENERIC_WRITE' : 0x40000000,
    'GENERIC_EXECUTE' : 0x20000000,
    'GENERIC_ALL' : 0x10000000,
    'MAXIMUM_ALLOWED' : 0x02000000,
    'ACCESS_SYSTEM_SECURITY' : 0x01000000,
    'SYNCHRONIZE' : 0x00100000,
    'WRITE_OWNER' : 0x00080000,
    'WRITE_DACL' : 0x00040000,
    'READ_CONTROL' : 0x00020000,
    'DELETE' : 0x00010000,
    # ACE type specific mask constants
    # Note that while not documented, these also seem valid
    # for ACCESS_ALLOWED_ACE types
    'ADS_RIGHT_DS_CONTROL_ACCESS' : 0x00000100,
    'ADS_RIGHT_DS_CREATE_CHILD' : 0x00000001,
    'ADS_RIGHT_DS_DELETE_CHILD' : 0x00000002,
    'ADS_RIGHT_DS_READ_PROP' : 0x00000010,
    'ADS_RIGHT_DS_WRITE_PROP' : 0x00000020,
    'ADS_RIGHT_DS_SELF' : 0x00000008
}

# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addauditaccessobjectace
ACE_FLAGS = {
    # Flag constants
    'CONTAINER_INHERIT_ACE' : 0x02,
    'FAILED_ACCESS_ACE_FLAG' : 0x80,
    'INHERIT_ONLY_ACE' : 0x08,
    'INHERITED_ACE' : 0x10,
    'NO_PROPAGATE_INHERIT_ACE' : 0x04,
    'OBJECT_INHERIT_ACE' : 0x01,
    'SUCCESSFUL_ACCESS_ACE_FLAG' : 0x40
}

# see https://social.technet.microsoft.com/wiki/contents/articles/37395.active-directory-schema-versions.aspx
SCHEMA_VERSION = {
    '13' : 'Windows 2000 Server',
    '30' : 'Windows Server 2003',
    '31' : 'Windows Server 2003 R2',
    '44' : 'Windows Server 2008',
    '47' : 'Windows Server 2008 R2',
    '56' : 'Windows Server 2012',
    '69' : 'Windows Server 2012 R2',
    '87' : 'Windows Server 2016',
    '88' : 'Windows Server 2019/2022'
}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d7422d35-448a-451a-8846-6a7def0044df?redirectedfrom=MSDN
FUNCTIONAL_LEVEL = {
    '0' : 'DS_BEHAVIOR_WIN2000',
    '1' : 'DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS',
    '2' : 'DS_BEHAVIOR_WIN2003',
    '3' : 'DS_BEHAVIOR_WIN2008',
    '4' : 'DS_BEHAVIOR_WIN2008R2',
    '5' : 'DS_BEHAVIOR_WIN2012',
    '6' : 'DS_BEHAVIOR_WIN2012R2',
    '7' : 'DS_BEHAVIOR_WIN2016'
}

# see https://docs.microsoft.com/fr-fr/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
ACCOUNT_FLAGS = {
    'SCRIPT' : 0x0001,
    'ACCOUNTDISABLE' : 0x0002,
    'HOMEDIR_REQUIRED' : 0x0008,
    'LOCKOUT' : 0x0010,
    'PASSWD_NOTREQD' : 0x0020,
    'PASSWD_CANT_CHANGE' : 0x0040,
    'ENCRYPTED_TEXT_PWD_ALLOWED' : 0x0080,
    'TEMP_DUPLICATE_ACCOUNT' : 0x0100,
    'NORMAL_ACCOUNT' : 0x0200,
    'INTERDOMAIN_TRUST_ACCOUNT' : 0x0800,
    'WORKSTATION_TRUST_ACCOUNT' : 0x1000,
    'SERVER_TRUST_ACCOUNT' : 0x2000,
    'DONT_EXPIRE_PASSWORD' : 0x10000,
    'MNS_LOGON_ACCOUNT' : 0x20000,
    'SMARTCARD_REQUIRED' : 0x40000,
    'TRUSTED_FOR_DELEGATION' : 0x80000,
    'NOT_DELEGATED' : 0x100000,
    'USE_DES_KEY_ONLY' : 0x200000,
    'DONT_REQ_PREAUTH' : 0x400000,
    'PASSWORD_EXPIRED' : 0x800000,
    'TRUSTED_TO_AUTH_FOR_DELEGATION' : 0x1000000,
    'PARTIAL_SECRETS_ACCOUNT' : 0x04000000
}

def decodeAccessMask(mask):
    pretty_mask = [key for key,val in ACCESS_FLAGS.items() if mask.hasPriv(val)]
    return pretty_mask if len(pretty_mask) > 0 else mask['Mask']


def decodeAceFlags(ace):
    pretty_flags = [key for key,val in ACE_FLAGS.items() if ace.hasFlag(val)]
    return pretty_flags if len(pretty_flags) > 0 else ace['AceFlags']


def ldap_search(base_dn, filter, attr):
    if not ldap_conn.search(base_dn, filter, attributes=attr) or not len(ldap_conn.entries) or attr not in ldap_conn.entries[0]:
        return None
    return ldap_conn.entries[0][attr].value

def resolveSid(sid):
    root_dn = ldap_conn.server.info.other['defaultNamingContext'][0]
    r = ldap_search(f"CN=WellKnown Security Principals,CN=Configuration,{root_dn}", f"(objectSid={sid})",'name')
    if r:
        return r
    r = ldap_search(root_dn, f"(objectSid={sid})",'sAMAccountName')
    return r if r else sid


def resolveGUID(guid_raw):
    attr = 'name'
    guid_canonical = str(uuid.UUID(bytes_le=guid_raw))
    guid_str = '\\'+'\\'.join(['{:02x}'.format(b) for b in guid_raw])
    schema_dn = ldap_conn.server.info.other['schemaNamingContext'][0]
    r = ldap_search(f"CN=Extended-Rights,{ldap_conn.server.info.other['configurationNamingContext'][0]}", f"(rightsGuid={guid_canonical})", attr)
    if not r:
        r = ldap_search(schema_dn, f"(schemaIDGUID={guid_str})", attr)
        return r if r else guid_canonical
    if not ldap_conn.search(schema_dn,f"(attributeSecurityGUID={guid_str})",attributes=attr) or not len(ldap_conn.entries):
        return r
    return {r:[entry[attr].value for entry in ldap_conn.entries]}


def formatSD(sd_bytes):
        sd=ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
        pretty_sd = {}
        if sd['OffsetOwner'] != 0:           
            pretty_sd['Owner'] = resolveSid(sd['OwnerSid'].formatCanonical())
        if sd['OffsetGroup'] != 0:
            pretty_sd['Group'] = resolveSid(sd['GroupSid'].formatCanonical())
        if sd['OffsetSacl'] != 0:
            pretty_sd['Sacl'] = base64.b64encode(sd['Sacl'].getData())
        if sd['OffsetDacl'] != 0:
            pretty_aces = []
            for ace in sd['Dacl'].aces:
                ace_val = ace['Ace']
                pretty_ace = {
                    'TypeName':ace['TypeName'], 
                    'Trustee': resolveSid(ace_val['Sid'].formatCanonical()),
                    'Mask':decodeAccessMask(ace_val['Mask'])
                }
                if ace['AceFlags'] > 0:
                    pretty_ace['Flags'] = decodeAceFlags(ace)
                if 'InheritedObjectType' in ace_val.__dict__['fields'] and len(ace_val['InheritedObjectType']) != 0:
                    pretty_ace['InheritedObjectType'] = resolveGUID(ace_val['InheritedObjectType'])
                if 'ObjectType' in ace_val.__dict__['fields'] and len(ace_val['ObjectType']) != 0:
                    pretty_ace['ObjectType'] = resolveGUID(ace_val['ObjectType'])
                pretty_aces.append(pretty_ace)
            pretty_sd['Dacl'] = pretty_aces
        return pretty_sd


def formatFunctionalLevel(behavior_version):
    behavior_version = behavior_version.decode()
    return FUNCTIONAL_LEVEL[behavior_version] if behavior_version in FUNCTIONAL_LEVEL else behavior_version


def formatSchemaVersion(objectVersion):
    objectVersion = objectVersion.decode()
    return SCHEMA_VERSION[objectVersion] if objectVersion in SCHEMA_VERSION else objectVersion


def formatAccountControl(userAccountControl):
    userAccountControl = int(userAccountControl.decode())
    return [key for key,val in ACCOUNT_FLAGS.items() if userAccountControl & val == val]


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]


def formatGMSApass(managedPassword):
    blob = MSDS_MANAGEDPASSWORD_BLOB(managedPassword)
    hash = MD4.new()
    hash.update(blob['CurrentPassword'][:-2])
    passwd = "aad3b435b51404eeaad3b435b51404ee:" + binascii.hexlify(hash.digest()).decode()
    return passwd

    
    

