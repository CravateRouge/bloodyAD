from bloodyAD.formatters.structure import Structure
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
