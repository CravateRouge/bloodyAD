from bloodyAD.formatters import (
    accesscontrol,
    common,
    cryptography,
    dns,
)
from bloodyAD.exceptions import LOG
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
    nt_hash = gmsa_blob.toNtHash()
    return {
        "NT": nt_hash,
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


from badldap.protocol.typeconversion import (
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


def getFormatters():
    """
    Returns a dictionary mapping attribute names to their formatting functions.
    This doesn't modify badldap's global dictionaries, allowing for local formatting.
    """
    def make_formatter(format_func):
        """Wrapper to handle list/non-list values consistently"""
        def wrapper(val):
            if isinstance(val, list):
                if len(val) == 1:
                    return format_func(val[0])
                else:
                    return [format_func(v) for v in val]
            else:
                return format_func(val)
        return wrapper
    
    def make_list_formatter(format_func):
        """Wrapper for formatters that expect the value as a list"""
        def wrapper(val):
            if isinstance(val, list):
                return format_func(val)
            else:
                return format_func([val])
        return wrapper
    
    formatters_map = {}
    
    # Security descriptors - expect single bytes value
    formatters_map["nTSecurityDescriptor"] = make_formatter(formatSD)
    formatters_map["msDS-AllowedToActOnBehalfOfOtherIdentity"] = make_formatter(formatSD)
    formatters_map["msDS-GroupMSAMembership"] = make_formatter(formatSD)
    
    # Passwords and credentials - expect single bytes value
    formatters_map["msDS-ManagedPassword"] = make_formatter(formatGMSApass)
    
    # Account control - expect single bytes value
    formatters_map["userAccountControl"] = make_formatter(formatAccountControl)
    formatters_map["msDS-User-Account-Control-Computed"] = make_formatter(formatAccountControl)
    
    # Trust attributes - expect single bytes value
    formatters_map["trustDirection"] = make_formatter(formatTrustDirection)
    formatters_map["trustAttributes"] = make_formatter(formatTrustAttributes)
    formatters_map["trustType"] = make_formatter(formatTrustType)
    
    # Versions and levels - expect single bytes value
    formatters_map["msDS-Behavior-Version"] = make_formatter(formatFunctionalLevel)
    formatters_map["objectVersion"] = make_formatter(formatSchemaVersion)
    
    # DNS and other - expect single bytes value
    formatters_map["dnsRecord"] = make_formatter(formatDnsRecord)
    formatters_map["msDS-KeyCredentialLink"] = make_formatter(formatKeyCredentialLink)
    formatters_map["wellKnownObjects"] = make_formatter(formatWellKnownObjects)
    
    # GUID and time attributes - these expect the value as a list
    formatters_map["attributeSecurityGUID"] = make_list_formatter(single_guid)
    formatters_map["msDS-MinimumPasswordAge"] = make_list_formatter(int2timedelta)
    
    return formatters_map


def applyFormatters(attributes, formatters_map):
    """
    Apply formatters to attributes dictionary.
    
    Args:
        attributes: Dictionary of attribute names to values
        formatters_map: Dictionary of attribute names to formatter functions
    
    Returns:
        Dictionary with formatted attributes
    """
    formatted_attrs = {}
    
    for attr_name, attr_value in attributes.items():
        if attr_name in formatters_map:
            formatter = formatters_map[attr_name]
            try:
                formatted_attrs[attr_name] = formatter(attr_value)
            except Exception as e:
                # If formatting fails, log the error and keep original value
                LOG.debug(
                    f"Failed to format attribute '{attr_name}': {type(e).__name__}: {e}"
                )
                formatted_attrs[attr_name] = attr_value
        else:
            formatted_attrs[attr_name] = attr_value
    
    return formatted_attrs


def enableEncoding():
    """
    Enable encoding support for specific attributes that need special encoding handling.
    This modifies badldap's encoding dictionaries but not the decoding/formatting logic.
    """
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC["msDS-AllowedToActOnBehalfOfOtherIdentity"] = (
        multi_bytes
    )


def enableFormatOutput():
    """
    DEPRECATED: This function modifies badldap's global dictionaries.
    It's kept for backward compatibility but should not be called by new code.
    Use getFormatters() and applyFormatters() instead.
    """
    enableEncoding()
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
