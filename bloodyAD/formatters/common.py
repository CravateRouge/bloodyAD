import binascii


class DNBinary:
    """
    Object(DN-Binary) - adschema
    """

    def __init__(self, data=None):
        if not data:
            return
        data = data.decode("utf-8").split(":")
        if len(data) != 4 or data[0] != "B":
            raise TypeError("can't convert str to DN-Binary")
        self.count = int(data[1])
        self.binary_value = data[2]

        self.value = binascii.unhexlify(self.binary_value)
        self.dn = data[3]

    def fromCanonical(self, value, dn):
        self.value = value
        self.dn = dn
        self.binary_value = binascii.hexlify(value).decode()
        self.count = len(self.binary_value)

    def __str__(self):
        return f"B:{self.count}:{self.binary_value}:{self.dn}"


# see https://social.technet.microsoft.com/wiki/contents/articles/37395.active-directory-schema-versions.aspx
SCHEMA_VERSION = {
    "13": "Windows 2000 Server",
    "30": "Windows Server 2003",
    "31": "Windows Server 2003 R2",
    "44": "Windows Server 2008",
    "47": "Windows Server 2008 R2",
    "56": "Windows Server 2012",
    "69": "Windows Server 2012 R2",
    "87": "Windows Server 2016",
    "88": "Windows Server 2019/2022",
}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d7422d35-448a-451a-8846-6a7def0044df?redirectedfrom=MSDN
FUNCTIONAL_LEVEL = {
    "0": "DS_BEHAVIOR_WIN2000",
    "1": "DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS",
    "2": "DS_BEHAVIOR_WIN2003",
    "3": "DS_BEHAVIOR_WIN2008",
    "4": "DS_BEHAVIOR_WIN2008R2",
    "5": "DS_BEHAVIOR_WIN2012",
    "6": "DS_BEHAVIOR_WIN2012R2",
    "7": "DS_BEHAVIOR_WIN2016",
}

# [MS-ADTS] - 6.1.1.4 Well-Known Objects
WELLKNOWN_GUID = {
    "AA312825768811D1ADED00C04FD8D5CD": "GUID_COMPUTERS_CONTAINER_W",
    "18E2EA80684F11D2B9AA00C04F79F805": "GUID_DELETED_OBJECTS_CONTAINER_W",
    "A361B2FFFFD211D1AA4B00C04FD7D83A": "GUID_DOMAIN_CONTROLLERS_CONTAINER_W",
    "22B70C67D56E4EFB91E9300FCA3DC1AA": "GUID_FOREIGNSECURITYPRINCIPALS_CONTAINER_W",
    "2FBAC1870ADE11D297C400C04FD8D5CD": "GUID_INFRASTRUCTURE_CONTAINER_W",
    "AB8153B7768811D1ADED00C04FD8D5CD": "GUID_LOSTANDFOUND_CONTAINER_W",
    "F4BE92A4C777485E878E9421D53087DB": "GUID_MICROSOFT_PROGRAM_DATA_CONTAINER_W",
    "6227F0AF1FC2410D8E3BB10615BB5B0F": "GUID_NTDS_QUOTAS_CONTAINER_W",
    "09460C08AE1E4A4EA0F64AEE7DAA1E5A": "GUID_PROGRAM_DATA_CONTAINER_W",
    "AB1D30F3768811D1ADED00C04FD8D5CD": "GUID_SYSTEMS_CONTAINER_W",
    "A9D1CA15768811D1ADED00C04FD8D5CD": "GUID_USERS_CONTAINER_W",
    "1EB93889E40C45DF9F0C64D23BBB6237": "GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER_W",
}

# [MS-ADTS] 6.1.6.7.12 trustDirection
TRUST_DIRECTION = {"DISABLED": 0, "INBOUND": 1, "OUTBOUND": 2, "BIDIRECTIONAL": 3}

# [MS-ADTS] 6.1.6.7.15 trustType
TRUST_TYPE = {"LOCAL_WINDOWS": 1, "AD": 2, "NON_WINDOWS": 3, "AZURE": 5}

# [MS-ADTS] 6.1.6.7.9 trustAttributes
TRUST_ATTRIBUTES = {
    "NON_TRANSITIVE": 0x1,
    "UPLEVEL_ONLY": 0x2,
    "QUARANTINED_DOMAIN": 0x4,
    "FOREST_TRANSITIVE": 0x8,
    "CROSS_ORGANIZATION": 0x10,
    "WITHIN_FOREST": 0x20,
    "TREAT_AS_EXTERNAL": 0x40,
    "USES_RC4_ENCRYPTION": 0x80,
    "CROSS_ORGANIZATION_NO_TGT_DELEGATION": 0x200,
    "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION": 0x800,
    "PIM_TRUST": 0x400,
}
