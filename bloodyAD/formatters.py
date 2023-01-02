import base64, binascii, uuid, ipaddress
from impacket.ldap import ldaptypes
from impacket.structure import Structure
from Cryptodome.Hash import MD4

ldap_conn = None


# https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
ACCESS_FLAGS = {
    # Flag constants
    "GENERIC_READ": 0x80000000,
    "GENERIC_WRITE": 0x40000000,
    "GENERIC_EXECUTE": 0x20000000,
    "GENERIC_ALL": 0x10000000,
    "MAXIMUM_ALLOWED": 0x02000000,
    "ACCESS_SYSTEM_SECURITY": 0x01000000,
    "SYNCHRONIZE": 0x00100000,
    # Not in the spec but equivalent to the flags below it
    "FULL_CONTROL": 0x000F01FF,
    "WRITE_OWNER": 0x00080000,
    "WRITE_DACL": 0x00040000,
    "READ_CONTROL": 0x00020000,
    "DELETE": 0x00010000,
    # ACE type specific mask constants
    # Note that while not documented, these also seem valid
    # for ACCESS_ALLOWED_ACE types
    "ADS_RIGHT_DS_CONTROL_ACCESS": 0x00000100,
    "ADS_RIGHT_DS_CREATE_CHILD": 0x00000001,
    "ADS_RIGHT_DS_DELETE_CHILD": 0x00000002,
    "ADS_RIGHT_DS_READ_PROP": 0x00000010,
    "ADS_RIGHT_DS_WRITE_PROP": 0x00000020,
    "ADS_RIGHT_DS_SELF": 0x00000008,
}

# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addauditaccessobjectace
ACE_FLAGS = {
    # Flag constants
    "CONTAINER_INHERIT_ACE": 0x02,
    "FAILED_ACCESS_ACE_FLAG": 0x80,
    "INHERIT_ONLY_ACE": 0x08,
    "INHERITED_ACE": 0x10,
    "NO_PROPAGATE_INHERIT_ACE": 0x04,
    "OBJECT_INHERIT_ACE": 0x01,
    "SUCCESSFUL_ACCESS_ACE_FLAG": 0x40,
}

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

# see https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
ACCOUNT_FLAGS = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
    "TEMP_DUPLICATE_ACCOUNT": 0x0100,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "MNS_LOGON_ACCOUNT": 0x20000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
}


def decodeAccessMask(mask):
    tmp_mask = [(key, val) for key, val in ACCESS_FLAGS.items() if mask.hasPriv(val)]
    pretty_mask = []
    for i in range(0, len(tmp_mask)):
        isDuplicate = False
        for j in range(i + 1, len(tmp_mask)):
            if tmp_mask[j][1] & tmp_mask[i][1] == tmp_mask[i][1]:
                isDuplicate = True
        for mask in pretty_mask:
            if mask[1] & tmp_mask[i][1] == tmp_mask[i][1]:
                isDuplicate = True
        if not isDuplicate:
            pretty_mask.append(tmp_mask[i])
    pretty_mask = [key for key, val in pretty_mask]
    return pretty_mask if len(pretty_mask) > 0 else mask["Mask"]


def decodeAceFlags(ace):
    pretty_flags = [key for key, val in ACE_FLAGS.items() if ace.hasFlag(val)]
    return pretty_flags if len(pretty_flags) > 0 else ace["AceFlags"]


def decodeAce(ace):
    ace_val = ace["Ace"]
    pretty_ace = {
        "TypeName": ace["TypeName"],
        "Trustee": resolveSid(ace_val["Sid"].formatCanonical()),
        "Mask": decodeAccessMask(ace_val["Mask"]),
    }
    if ace["AceFlags"] > 0:
        pretty_ace["Flags"] = decodeAceFlags(ace)
    if (
        "InheritedObjectType" in ace_val.__dict__["fields"]
        and len(ace_val["InheritedObjectType"]) != 0
    ):
        pretty_ace["InheritedObjectType"] = resolveGUID(ace_val["InheritedObjectType"])
    if "ObjectType" in ace_val.__dict__["fields"] and len(ace_val["ObjectType"]) != 0:
        pretty_ace["ObjectType"] = resolveGUID(ace_val["ObjectType"])

    return pretty_ace


def ldap_search(base_dn, filter, attr):
    try:
        if (
            not ldap_conn.search(base_dn, filter, attributes=attr)
            or not len(ldap_conn.entries)
            or attr not in ldap_conn.entries[0]
        ):
            return None
    except:
        return None

    return ldap_conn.entries[0][attr].value


def resolveSid(sid):
    r = ldap_search(
        "CN=WellKnown Security"
        f" Principals,{ldap_conn.server.info.other['configurationNamingContext'][0]}",
        f"(objectSid={sid})",
        "name",
    )
    if r:
        return r
    r = ldap_search(
        ldap_conn.server.info.other["rootDomainNamingContext"][0],
        f"(objectSid={sid})",
        "sAMAccountName",
    )
    return r if r else sid


def resolveGUID(guid_raw):
    attr = "name"
    guid_canonical = str(uuid.UUID(bytes_le=guid_raw))
    guid_str = "\\" + "\\".join(["{:02x}".format(b) for b in guid_raw])
    schema_dn = ldap_conn.server.info.other["schemaNamingContext"][0]
    r = ldap_search(
        f"CN=Extended-Rights,{ldap_conn.server.info.other['configurationNamingContext'][0]}",
        f"(rightsGuid={guid_canonical})",
        attr,
    )
    if not r:
        r = ldap_search(schema_dn, f"(schemaIDGUID={guid_str})", attr)
        return r if r else guid_canonical
    if not ldap_conn.search(
        schema_dn, f"(attributeSecurityGUID={guid_str})", attributes=attr
    ) or not len(ldap_conn.entries):
        return r
    return {r: [entry[attr].value for entry in ldap_conn.entries]}


def formatSD(sd_bytes):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    pretty_sd = {}
    if sd["OffsetOwner"] != 0:
        pretty_sd["Owner"] = resolveSid(sd["OwnerSid"].formatCanonical())
    if sd["OffsetGroup"] != 0:
        pretty_sd["Group"] = resolveSid(sd["GroupSid"].formatCanonical())
    if sd["OffsetSacl"] != 0:
        pretty_sd["Sacl"] = base64.b64encode(sd["Sacl"].getData())
    if sd["OffsetDacl"] != 0:
        pretty_aces = []
        for ace in sd["Dacl"].aces:
            pretty_aces.append(decodeAce(ace))
        pretty_sd["Dacl"] = pretty_aces
    return pretty_sd


def formatFunctionalLevel(behavior_version):
    behavior_version = behavior_version.decode()
    return (
        FUNCTIONAL_LEVEL[behavior_version]
        if behavior_version in FUNCTIONAL_LEVEL
        else behavior_version
    )


def formatSchemaVersion(objectVersion):
    objectVersion = objectVersion.decode()
    return (
        SCHEMA_VERSION[objectVersion]
        if objectVersion in SCHEMA_VERSION
        else objectVersion
    )


def formatAccountControl(userAccountControl):
    userAccountControl = int(userAccountControl.decode())
    return [
        key for key, val in ACCOUNT_FLAGS.items() if userAccountControl & val == val
    ]


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ("Version", "<H"),
        ("Reserved", "<H"),
        ("Length", "<L"),
        ("CurrentPasswordOffset", "<H"),
        ("PreviousPasswordOffset", "<H"),
        ("QueryPasswordIntervalOffset", "<H"),
        ("UnchangedPasswordIntervalOffset", "<H"),
        ("CurrentPassword", ":"),
        ("PreviousPassword", ":"),
        # ('AlignmentPadding',':'),
        ("QueryPasswordInterval", ":"),
        ("UnchangedPasswordInterval", ":"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data):
        Structure.fromString(self, data)

        if self["PreviousPasswordOffset"] == 0:
            endData = self["QueryPasswordIntervalOffset"]
        else:
            endData = self["PreviousPasswordOffset"]

        self["CurrentPassword"] = self.rawData[self["CurrentPasswordOffset"] :][
            : endData - self["CurrentPasswordOffset"]
        ]
        if self["PreviousPasswordOffset"] != 0:
            self["PreviousPassword"] = self.rawData[self["PreviousPasswordOffset"] :][
                : self["QueryPasswordIntervalOffset"] - self["PreviousPasswordOffset"]
            ]

        self["QueryPasswordInterval"] = self.rawData[
            self["QueryPasswordIntervalOffset"] :
        ][
            : self["UnchangedPasswordIntervalOffset"]
            - self["QueryPasswordIntervalOffset"]
        ]
        self["UnchangedPasswordInterval"] = self.rawData[
            self["UnchangedPasswordIntervalOffset"] :
        ]


def formatGMSApass(managedPassword):
    blob = MSDS_MANAGEDPASSWORD_BLOB(managedPassword)
    hash = MD4.new()
    hash.update(blob["CurrentPassword"][:-2])
    passwd = (
        "aad3b435b51404eeaad3b435b51404ee:" + binascii.hexlify(hash.digest()).decode()
    )
    return passwd


# Credits to dirkjanm and his tool adidnsdump
"""
DNS_RECORD_TYPE - [MS-DNSP] section 2.2.2.1.1
Prefix DNS_TYPE_ has been removed for implementation purposes and only a subset of constants is implemented
"""
DNS_RECORD_TYPE = {
    "A": 0x1,
    "AAAA": 0x1C,
    "CNAME": 0x5,
    "MX": 0xF,
    "PTR": 0xC,
    "SRV": 0x21,
    "TXT": 0x10,
    "NS": 0x2,
    "SOA": 0x6,
}


class dnsRecord(Structure):
    """
    dnsRecord - [MS-DNSP] section 2.3.2.2
    """

    structure = (
        ("DataLength", "<H-Data"),
        ("Type", "<H"),
        ("Version", "B=5"),
        ("Rank", "B"),
        ("Flags", "<H=0"),
        ("Serial", "<I"),
        ("TtlSeconds", ">I"),
        ("Reserved", "<I=0"),
        ("TimeStamp", "<I=0"),
        ("Data", ":"),
    )

    def toDict(self):
        dnstype = None
        for k, v in DNS_RECORD_TYPE.items():
            if self["Type"] == v:
                dnstype = k

        record_data = None
        if dnstype == "A":
            record_data = DNS_RPC_RECORD_A(self["Data"]).toDict()
        elif dnstype == "AAAA":
            record_data = DNS_RPC_RECORD_AAAA(self["Data"]).toDict()
        elif dnstype in ["NS", "CNAME", "PTR"]:
            record_data = DNS_RPC_RECORD_NODE_NAME(self["Data"]).toDict()
        elif dnstype == "MX":
            record_data = DNS_RPC_RECORD_NAME_PREFERENCE(self["Data"]).toDict()
        elif dnstype == "SRV":
            record_data = DNS_RPC_RECORD_SRV(self["Data"]).toDict()
        elif dnstype == "TXT":
            record_data = DNS_RPC_RECORD_STRING(self["Data"]).formatCanonical()
        elif dnstype == "SOA":
            record_data = DNS_RPC_RECORD_SOA(self["Data"]).toDict()
        else:
            dnstype = self["Type"]
            record_data = self["Data"]

        return {"Data": record_data, "Type": dnstype, "TtlSeconds": self["TtlSeconds"]}

    def fromDict(
        self,
        data,
        dnstype,
        ttl,
        rank,
        serial,
        preference=None,
        port=None,
        priority=None,
        weight=None,
    ):
        self["Rank"] = rank
        self["Serial"] = serial
        self["Type"] = DNS_RECORD_TYPE[dnstype]
        self["TtlSeconds"] = ttl

        if dnstype == "A":
            record_data = DNS_RPC_RECORD_A()
            record_data.fromCanonical(data)
        elif dnstype == "AAAA":
            record_data = DNS_RPC_RECORD_AAAA()
            record_data.fromCanonical(data)
        elif dnstype in ["NS", "CNAME", "PTR"]:
            record_data = DNS_RPC_RECORD_NODE_NAME()
            record_data.fromCanonical(data)
        elif dnstype == "MX":
            record_data = DNS_RPC_RECORD_NAME_PREFERENCE()
            record_data.fromCanonical(data, preference)
        elif dnstype == "SRV":
            record_data = DNS_RPC_RECORD_SRV()
            record_data.fromCanonical(data, port, priority, weight)
        elif dnstype == "TXT":
            record_data = DNS_RPC_RECORD_STRING()
            record_data.fromCanonical(data)
        else:
            raise TypeError(f"{dnstype} not supported")

        self["Data"] = record_data


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A - [MS-DNSP] section 2.2.2.2.4.1
    """

    structure = (("address", "!I"),)

    def toDict(self):
        return self.formatCanonical()

    def formatCanonical(self):
        return str(ipaddress.IPv4Address(self["address"]))

    def fromCanonical(self, canonical):
        self["address"] = int(ipaddress.IPv4Address(canonical))


class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA - [MS-DNSP] section 2.2.2.2.4.17
    """

    structure = (("ipv6Address", "!16s"),)

    def toDict(self):
        return self.formatCanonical()

    def formatCanonical(self):
        return str(ipaddress.IPv6Address(self["ipv6Address"]))

    def fromCanonical(self, canonical):
        self["ipv6Address"] = ipaddress.IPv6Address(canonical).packed


class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME - [MS-DNSP] section 2.2.2.2.2
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    """

    structure = (("Length", "B-RawName"), ("LabelCount", "B"), ("RawName", ":"))

    def formatCanonical(self):
        ind = 0
        labels = []
        for i in range(self["LabelCount"]):
            nextlen = int.from_bytes(self["RawName"][ind : ind + 1], byteorder="big")
            labels.append(self["RawName"][ind + 1 : ind + 1 + nextlen].decode("utf-8"))
            ind += nextlen + 1
        # For the final dot
        labels.append("")
        return ".".join(labels)

    def fromCanonical(self, canonical):
        # Removes empty strings
        labels = [label for label in canonical.split(".") if label]
        label_count = 0
        raw_name = b""
        for label in labels:
            label_count += 1
            raw_name += len(label).to_bytes(1, byteorder="big") + label.encode("utf-8")
        raw_name += b"\x00"
        self["LabelCount"] = label_count
        self["RawName"] = raw_name


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME - [MS-DNSP] section 2.2.2.2.4.2
    Used for CNAME records
    """

    structure = (("nameNode", ":", DNS_COUNT_NAME),)

    def toDict(self):
        return self["nameNode"].formatCanonical()

    def fromCanonical(self, canonical):
        record_name = DNS_COUNT_NAME()
        record_name.fromCanonical(canonical)
        self["nameNode"] = record_name


class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE - [MS-DNSP] section 2.2.2.2.4.8
    Used for MX records
    """

    structure = (("wPreference", ">H"), ("nameExchange", ":", DNS_COUNT_NAME))

    def toDict(self):
        return {
            "Name": self["nameExchange"].formatCanonical(),
            "Preference": self["wPreference"],
        }

    def fromCanonical(self, fqdn, preference):
        self["wPreference"] = preference
        record_name = DNS_COUNT_NAME()
        record_name.fromCanonical(fqdn)
        self["nameExchange"] = record_name


class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV - [MS-DNSP] section 2.2.2.2.4.18
    """

    structure = (
        ("wPriority", ">H"),
        ("wWeight", ">H"),
        ("wPort", ">H"),
        ("nameTarget", ":", DNS_COUNT_NAME),
    )

    def toDict(self):
        return {
            "Target": self["nameTarget"].formatCanonical(),
            "Port": self["wPort"],
            "Priority": self["wPriority"],
            "Weight": self["wWeight"],
        }

    def fromCanonical(self, fqdn, port, priority, weight):
        self["wPriority"] = priority
        self["wWeight"] = weight
        self["wPort"] = port
        record_name = DNS_COUNT_NAME()
        record_name.fromCanonical(fqdn)
        self["nameTarget"] = record_name


class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME - [MS-DNSP] section 2.2.2.2.1
    Used for FQDN in RPC communications and other strings
    """

    structure = (("cchNameLength", "B-dnsName"), ("dnsName", ":"))

    def formatCanonical(self):
        return self["dnsName"].decode("utf-8")


class DNS_RPC_RECORD_STRING(Structure):
    """
    DNS_RPC_RECORD_STRING - [MS-DNSP] section 2.2.2.2.4.6
    Used for TXT records
    """

    structure = (("stringData", ":", DNS_RPC_NAME),)

    def formatCanonical(self):
        return self["stringData"].formatCanonical()

    def fromCanonical(self, canonical):
        data_container = DNS_RPC_NAME()
        data_container["dnsName"] = canonical.encode("utf-8")
        self["stringData"] = data_container


class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA - [MS-DNSP] section 2.2.2.2.4.3
    """

    structure = (
        ("dwSerialNo", ">I"),
        ("dwRefresh", ">I"),
        ("dwRetry", ">I"),
        ("dwExpire", ">I"),
        ("dwMinimumTtl", ">I"),
        ("namePrimaryServer", ":", DNS_COUNT_NAME),
        ("zoneAdminEmail", ":", DNS_COUNT_NAME),
    )

    def toDict(self):
        return {
            "SerialNo": self["dwSerialNo"],
            "Refresh": self["dwRefresh"],
            "Retry": self["dwRetry"],
            "Expire": self["dwExpire"],
            "MinimumTtl": self["dwMinimumTtl"],
            "PrimaryServer": self["namePrimaryServer"].formatCanonical(),
            "zoneAdminEmail": self["zoneAdminEmail"].formatCanonical(),
        }


def formatDnsRecord(dns_record):
    return dnsRecord(dns_record).toDict()
