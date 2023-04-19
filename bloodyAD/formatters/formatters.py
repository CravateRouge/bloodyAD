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
