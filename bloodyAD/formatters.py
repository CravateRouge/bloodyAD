
import base64
from impacket.ldap import ldaptypes

def decodeAccessMask(mask):
    flags = {
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
    pretty_mask = [key for key,val in flags.items() if mask.hasPriv(val)]
    return pretty_mask if len(pretty_mask) > 0 else mask['Mask']


def decodeAceFlags(ace):
    flags = {
    # Flag constants
    'CONTAINER_INHERIT_ACE' : 0x02,
    'FAILED_ACCESS_ACE_FLAG' : 0x80,
    'INHERIT_ONLY_ACE' : 0x08,
    'INHERITED_ACE' : 0x10,
    'NO_PROPAGATE_INHERIT_ACE' : 0x04,
    'OBJECT_INHERIT_ACE' : 0x01,
    'SUCCESSFUL_ACCESS_ACE_FLAG' : 0x40
    }
    pretty_flags = [key for key,val in flags.items() if ace.hasFlag(val)]
    return pretty_flags if len(pretty_flags) > 0 else ace['AceFlags']


def decodeGuid(guid):
    part_sizes = [4,6,8,10]
    pretty_guid = ''
    i = 0
    while i < len(guid):
        pretty_guid += f'{guid[i]:x}'
        i += 1
        if i in part_sizes:
            pretty_guid += f'-'
    return pretty_guid


def formatSD(sd_bytes):
        sd=ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
        pretty_sd = {}
        if sd['OffsetOwner'] != 0:
            pretty_sd['OwnerSid'] = sd['OwnerSid'].formatCanonical()
        if sd['OffsetGroup'] != 0:
            pretty_sd['GroupSid'] = sd['GroupSid'].formatCanonical()
        if sd['OffsetSacl'] != 0:
            pretty_sd['Sacl'] = base64.b64encode(sd['Sacl'].getData())
        if sd['OffsetDacl'] != 0:
            pretty_aces = []
            for ace in sd['Dacl'].aces:
                ace_val = ace['Ace']
                pretty_ace = {
                    'TypeName':ace['TypeName'], 
                    'Sid':ace_val['Sid'].formatCanonical(),
                    'Mask':decodeAccessMask(ace_val['Mask'])
                }
                if ace['AceFlags'] > 0:
                    pretty_ace['Flags'] = decodeAceFlags(ace)
                if 'ObjectType' in ace_val.__dict__['fields'] and len(ace_val['ObjectType']) != 0:
                    pretty_ace['ObjectType'] = decodeGuid(ace_val['ObjectType'])
                if 'InheritedObjectType' in ace_val.__dict__['fields'] and len(ace_val['InheritedObjectType']) != 0:
                    pretty_ace['InheritedObjectType'] = decodeGuid(ace_val['InheritedObjectType'])
                pretty_aces.append(pretty_ace)
            pretty_sd['Dacl'] = pretty_aces
        return pretty_sd

def formatVersion(objectVersion):
    objectVersion = objectVersion.decode()
    # see https://social.technet.microsoft.com/wiki/contents/articles/37395.active-directory-schema-versions.aspx
    ADversion = {
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
    return ADversion[objectVersion] if objectVersion in ADversion else objectVersion

def formatAccountControl(userAccountControl):
    userAccountControl = int(userAccountControl.decode())
    
    # see https://docs.microsoft.com/fr-fr/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    accountCodes = {
       0x0001:'SCRIPT',
       0x0002:'ACCOUNTDISABLE',
       0x0008:'HOMEDIR_REQUIRED',
       0x0010:'LOCKOUT',
       0x0020:'PASSWD_NOTREQD',
       0x0040:'PASSWD_CANT_CHANGE',
       0x0080:'ENCRYPTED_TEXT_PWD_ALLOWED',
       0x0100:'TEMP_DUPLICATE_ACCOUNT',
       0x0200:'NORMAL_ACCOUNT',
       0x0800:'INTERDOMAIN_TRUST_ACCOUNT',
       0x1000:'WORKSTATION_TRUST_ACCOUNT',
       0x2000:'SERVER_TRUST_ACCOUNT',
       0x10000:'DONT_EXPIRE_PASSWORD',
       0x20000:'MNS_LOGON_ACCOUNT',
       0x40000:'SMARTCARD_REQUIRED',
       0x80000:'TRUSTED_FOR_DELEGATION',
       0x100000:'NOT_DELEGATED',
       0x200000:'USE_DES_KEY_ONLY',
       0x400000:'DONT_REQ_PREAUTH',
       0x800000:'PASSWORD_EXPIRED',
       0x1000000:'TRUSTED_TO_AUTH_FOR_DELEGATION',
       0x04000000:'PARTIAL_SECRETS_ACCOUNT'
    }

    return [val for key,val in accountCodes.items() if userAccountControl & key == key]
    
    

