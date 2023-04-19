from bloodyAD.formatters.structure import Structure
from bloodyAD import md4
import hashlib
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class BCRYPT_RSAKEY_BLOB(Structure):
    structure = (
        ("Magic", "<I=0x31415352"),
        ("BitLength", "<I=2048"),
        ("cbPublicExp", "<I=3"),
        ("cbModulus", "<I=256"),
        ("cbPrime1", "<I=0"),
        ("cbPrime2", "<I=0"),
        ("exponent", "3s"),
        ("modulus", "256s"),
    )


class KEYCREDENTIALLINK_ENTRY(Structure):
    """
    KEYCREDENTIALLINK_ENTRY - [MS-ADTS] section 2.2.20.3
    """

    # KEYCREDENTIALLINK_ENTRY Identifiers - [MS-ADTS] 2.2.20.6
    identifiers = {
        "KeyID": 0x01,
        "KeyHash": 0x02,
        "KeyMaterial": 0x03,
        "KeyUsage": 0x04,
        "KeySource": 0x05,
        "DeviceId": 0x06,
        "CustomKeyInformation": 0x07,
        "KeyApproximateLastLogonTimeStamp": 0x08,
        "KeyCreationTime": 0x09,
    }

    # Key Credential Link Constants - [MS-ADTS] 2.2.20.1
    KeyUsage_values = {
        "KEY_USAGE_NGC": 0x01,
        "KEY_USAGE_FIDO": 0x07,
        "KEY_USAGE_FEK": 0x08,
    }
    KEY_SOURCE_AD = 0

    commonHdr = (("Length", "<H-Value"), ("Identifier", "<B"))

    structure = (("Value", ":"),)

    def __init__(self, data=None, identifier=None, **kwargs):
        super().__init__(data, **kwargs)

        if identifier:
            self["Identifier"] = self.identifiers[identifier]

    def toDict(self):
        identifier = [
            i for i in self.identifiers if self.identifiers[i] == self["Identifier"]
        ][0]
        return {identifier: self["Value"].hex()}


class KEYCREDENTIALLINK_BLOB(Structure):
    """
    KEYCREDENTIALLINK_BLOB - [MS-ADTS] section 2.2.20.2
    """

    KEY_CREDENTIAL_LINK_VERSION_2 = 0x200

    commonHdr = (("Version", "<I=self.KEY_CREDENTIAL_LINK_VERSION_2"),)
    structure = (("KEYCREDENTIALLINK_ENTRY_LIST", "*:", KEYCREDENTIALLINK_ENTRY),)

    # Structure class doesn't handle correctly unpacking variable size array with custom format
    # so we have to do it ourselves. First we take it as raw data and then we're unpacking it
    # using the underlying entry structure with header length
    def __init__(self, data=None, **kwargs):
        if data:
            self.structure = (("KEYCREDENTIALLINK_ENTRY_LIST", ":"),)
            super().__init__(data, **kwargs)
            raw_blob = self["KEYCREDENTIALLINK_ENTRY_LIST"]
            entries = []
            while raw_blob:
                entry = KEYCREDENTIALLINK_ENTRY(raw_blob)
                # if entry["Identifier"] not in [entry.identifiers["CustomKeyInformation"], entry.identifiers["KeyApproximateLastLogonTimeStamp"], entry.identifiers["KeyCreationTime"], entry.identifiers["DeviceId"], entry.identifiers["DeviceId"], entry.identifiers["KeyHash"], entry.identifiers["KeyUsage"], entry.identifiers["KeySource"]]:
                entries.append(entry)
                raw_blob = raw_blob[2 + 1 + entry["Length"] :]

            self.structure = (
                ("KEYCREDENTIALLINK_ENTRY_LIST", "*:", KEYCREDENTIALLINK_ENTRY),
            )
            self["KEYCREDENTIALLINK_ENTRY_LIST"] = entries
        else:
            super().__init__(data, **kwargs)

    # Here I just put mandatory entries, could evolve in the future
    def keyCredentialLink_from_x509(self, cert):
        key_material = KEYCREDENTIALLINK_ENTRY(identifier="KeyMaterial")

        # We use standard format mentioned in [MS-ADTS] 2.2.20.5.1 KEY_USAGE_NGC
        # and specified as RSAPublicKey in rfc8017 Appendix C - Main structures - p.72
        # BCRYPT_RSAKEY_BLOB is another option undocumented in [MS-ADTS]
        key_material["Value"] = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.PKCS1
        )

        key_id = KEYCREDENTIALLINK_ENTRY(identifier="KeyID")
        key_id["Value"] = hashlib.sha256(key_material["Value"]).digest()

        self["KEYCREDENTIALLINK_ENTRY_LIST"] = [key_id, key_material]

    def toDict(self):
        return {
            k: v
            for entry in self["KEYCREDENTIALLINK_ENTRY_LIST"]
            for k, v in entry.toDict().items()
        }

    def getKeyID(self):
        return [
            entry["Value"]
            for entry in self["KEYCREDENTIALLINK_ENTRY_LIST"]
            if entry["Identifier"] == entry.identifiers["KeyID"]
        ][0]


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ("Version", "<H=0x01"),
        ("Reserved", "<H=0x00"),
        ("Length", "<I"),
        ("CurrentPasswordOffset", "<H"),
        ("PreviousPasswordOffset", "<H"),
        ("QueryPasswordIntervalOffset", "<H"),
        ("UnchangedPasswordIntervalOffset", "<H"),
        ("CurrentPassword", "u"),
        ("PreviousPassword", "u"),
        # ('AlignmentPadding',':'),
        ("QueryPasswordInterval", "<Q"),
        ("UnchangedPasswordInterval", "<Q"),
    )

    def toNtHash(self):
        return md4.MD4(self["CurrentPassword"]).hexdigest()
