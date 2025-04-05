from bloodyAD.formatters import (
    accesscontrol,
    common,
    cryptography,
    dns,
)
import base64
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR


def formatAccountControl(userAccountControl):
    userAccountControl = int(userAccountControl.decode())
    return [
        key
        for key, val in accesscontrol.ACCOUNT_FLAGS.items()
        if userAccountControl & val == val
    ]


def formatTrustDirection(trustDirection):
    trustDirection = int(trustDirection.decode())
    for key, val in common.TRUST_DIRECTION.items():
        if trustDirection == val:
            return key
    return trustDirection


def formatTrustAttributes(trustAttributes):
    trustAttributes = int(trustAttributes.decode())
    return [
        key
        for key, val in common.TRUST_ATTRIBUTES.items()
        if trustAttributes & val == val
    ]


def formatTrustType(trustType):
    trustType = int(trustType.decode())
    for key, val in common.TRUST_TYPE.items():
        if trustType == val:
            return key
    return trustType


def formatSD(sd_bytes):
    return SECURITY_DESCRIPTOR.from_bytes(sd_bytes).to_sddl()


def formatFunctionalLevel(behavior_version):
    behavior_version = behavior_version.decode()
    return (
        common.FUNCTIONAL_LEVEL[behavior_version]
        if behavior_version in common.FUNCTIONAL_LEVEL
        else behavior_version
    )


def formatSchemaVersion(objectVersion):
    objectVersion = objectVersion.decode()
    return (
        common.SCHEMA_VERSION[objectVersion]
        if objectVersion in common.SCHEMA_VERSION
        else objectVersion
    )


def formatGMSApass(managedPassword):
    gmsa_blob = cryptography.MSDS_MANAGEDPASSWORD_BLOB(managedPassword)
    ntlm_hash = "aad3b435b51404eeaad3b435b51404ee:" + gmsa_blob.toNtHash()
    return {
        "NTLM": ntlm_hash,
        "B64ENCODED": base64.b64encode(gmsa_blob["CurrentPassword"]).decode(),
    }


def formatDnsRecord(dns_record):
    return dns.Record(dns_record).toDict()


def formatWellKnownObjects(wellKnown_object):
    dn_binary = common.DNBinary(wellKnown_object)
    if dn_binary.binary_value in common.WELLKNOWN_GUID:
        dn_binary.binary_value = common.WELLKNOWN_GUID[dn_binary.binary_value]
    return dn_binary


def formatKeyCredentialLink(key_dnbinary):
    return cryptography.KEYCREDENTIALLINK_BLOB(
        common.DNBinary(key_dnbinary).value
    ).toDict()


from msldap.protocol.typeconversion import (
    LDAP_WELL_KNOWN_ATTRS,
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES,
    single_guid,
    multi_bytes,
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC,
    int2timedelta,
)


def formatFactory(format_func, origin_format):
    def genericFormat(val, encode=False, *args):
        if encode:
            return origin_format(val, encode, *args)
        if not isinstance(val, list):
            return format_func(val)
        return [format_func(e) for e in val]
    # The function name is set to the original function name for encode changes logic
    genericFormat.__name__ = origin_format.__name__
    return genericFormat


MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC["msDS-AllowedToActOnBehalfOfOtherIdentity"] = (
    multi_bytes
)
MSLDAP_BUILTIN_ATTRIBUTE_TYPES["nTSecurityDescriptor"] = formatFactory(
    formatSD, MSLDAP_BUILTIN_ATTRIBUTE_TYPES["nTSecurityDescriptor"]
)
MSLDAP_BUILTIN_ATTRIBUTE_TYPES["msDS-AllowedToActOnBehalfOfOtherIdentity"] = (
    formatFactory(formatSD, multi_bytes)
)
MSLDAP_BUILTIN_ATTRIBUTE_TYPES["msDS-GroupMSAMembership"] = formatFactory(
    formatSD, MSLDAP_BUILTIN_ATTRIBUTE_TYPES["msDS-GroupMSAMembership"]
)
MSLDAP_BUILTIN_ATTRIBUTE_TYPES["msDS-ManagedPassword"] = formatFactory(
    formatGMSApass, MSLDAP_BUILTIN_ATTRIBUTE_TYPES["msDS-ManagedPassword"]
)
MSLDAP_BUILTIN_ATTRIBUTE_TYPES["userAccountControl"] = formatFactory(
    formatAccountControl, MSLDAP_BUILTIN_ATTRIBUTE_TYPES["userAccountControl"]
)
LDAP_WELL_KNOWN_ATTRS["msDS-User-Account-Control-Computed"] = formatFactory(
    formatAccountControl, LDAP_WELL_KNOWN_ATTRS["msDS-User-Account-Control-Computed"]
)
LDAP_WELL_KNOWN_ATTRS["trustDirection"] = formatFactory(
    formatTrustDirection, LDAP_WELL_KNOWN_ATTRS["trustDirection"]
)
LDAP_WELL_KNOWN_ATTRS["trustAttributes"] = formatFactory(
    formatTrustAttributes, LDAP_WELL_KNOWN_ATTRS["trustAttributes"]
)
LDAP_WELL_KNOWN_ATTRS["trustType"] = formatFactory(
    formatTrustType, LDAP_WELL_KNOWN_ATTRS["trustType"]
)
MSLDAP_BUILTIN_ATTRIBUTE_TYPES["msDS-Behavior-Version"] = formatFactory(
    formatFunctionalLevel, MSLDAP_BUILTIN_ATTRIBUTE_TYPES["msDS-Behavior-Version"]
)
LDAP_WELL_KNOWN_ATTRS["objectVersion"] = formatFactory(
    formatSchemaVersion, LDAP_WELL_KNOWN_ATTRS["objectVersion"]
)
LDAP_WELL_KNOWN_ATTRS["dnsRecord"] = formatFactory(
    formatDnsRecord, LDAP_WELL_KNOWN_ATTRS["dnsRecord"]
)
LDAP_WELL_KNOWN_ATTRS["msDS-KeyCredentialLink"] = formatFactory(
    formatKeyCredentialLink, LDAP_WELL_KNOWN_ATTRS["msDS-KeyCredentialLink"]
)
LDAP_WELL_KNOWN_ATTRS["attributeSecurityGUID"] = single_guid
LDAP_WELL_KNOWN_ATTRS["wellKnownObjects"] = formatFactory(
    formatWellKnownObjects, LDAP_WELL_KNOWN_ATTRS["wellKnownObjects"]
)
LDAP_WELL_KNOWN_ATTRS["msDS-MinimumPasswordAge"] = int2timedelta

from winacl.dtyp.ace import (
    SYSTEM_AUDIT_OBJECT_ACE,
    SDDL_ACE_TYPE_MAPS_INV,
    aceflags_to_sddl,
    accessmask_to_sddl,
    ACE_OBJECT_PRESENCE,
)


def to_sddl(self, sd_object_type=None):
    # ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
    return "(%s;%s;%s;%s;%s;%s)" % (
        SDDL_ACE_TYPE_MAPS_INV[self.AceType],
        aceflags_to_sddl(self.AceFlags),
        accessmask_to_sddl(self.Mask, self.sd_object_type),
        (
            self.ObjectType.to_bytes()
            if self.AceFlags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
            else ""
        ),
        (
            self.InheritedObjectType.to_bytes()
            if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT
            else ""
        ),
        self.Sid.to_sddl(),
    )


setattr(SYSTEM_AUDIT_OBJECT_ACE, "to_sddl", to_sddl)
