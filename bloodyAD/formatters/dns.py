from bloodyAD.formatters.structure import Structure
import ipaddress

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


class Record(Structure):
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

        self["Data"] = record_data.getData()


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
        # For the final dot, but do we really want to display it?
        # labels.append("")
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
