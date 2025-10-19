import binascii
from typing import Literal
import badldap
from bloodyAD import utils, ConnectionHandler
from bloodyAD.exceptions import LOG
from bloodyAD.formatters import accesscontrol, common, dns, cryptography
from bloodyAD.exceptions import BloodyError
from bloodyAD.network.ldap import Change


async def dcsync(conn: ConnectionHandler, trustee: str):
    """
    Remove DCSync right for provided trustee

    :param trustee: sAMAccountName, DN or SID of the trustee
    """
    ldap = await conn.getLdap()
    new_sd, _ = await utils.getSD(conn, ldap.domainNC)
    if "s-1-" in trustee.lower():
        trustee_sid = trustee
    else:
        entry = None
        async for e in ldap.bloodysearch(trustee, attr=["objectSid"]):
            entry = e
            break
        trustee_sid = entry["objectSid"]
    access_mask = accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
    utils.delRight(new_sd, trustee_sid, access_mask)

    req_flags = badldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
        {"Flags": accesscontrol.DACL_SECURITY_INFORMATION}
    )
    controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

    await ldap.bloodymodify(
        ldap.domainNC,
        {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
        controls,
    )

    LOG.info(f"{trustee} can't DCSync anymore")


async def dnsRecord(
    conn: ConnectionHandler,
    name: str,
    data: str,
    dnstype: Literal["A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT"] = "A",
    zone: str = "CurrentDomain",
    ttl: int = None,
    preference: int = None,
    port: int = None,
    priority: int = None,
    weight: int = None,
    forest: bool = False,
):
    """
    Remove a DNS record of an AD environment.

    :param name: name of the dnsNode object (hostname) which contains the record
    :param data: DNS record data
    :param dnstype: DNS record type
    :param zone: DNS zone
    :param ttl: DNS record TTL
    :param preference: DNS MX record preference
    :param port: listening port of the service in a DNS SRV record
    :param priority: priority of a DNS SRV record against concurrent
    :param weight: weight of a DNS SRV record against concurrent
    :param forest: if set, will fetch the dns record in forest instead of domain
    """

    ldap = await conn.getLdap()
    naming_context = "," + ldap.domainNC
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

    zone_dn = f",DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}"
    record_dn = f"DC={name}{zone_dn}"

    record_to_remove = None
    entry = None
    async for e in ldap.bloodysearch(record_dn, attr=["dnsRecord"], raw=True):
        entry = e
        break
    dns_list = entry["dnsRecord"]
    for raw_record in dns_list:
        record = dns.Record(raw_record)
        tmp_record = dns.Record()

        if not ttl:
            ttl = record["TtlSeconds"]
        tmp_record.fromDict(
            data,
            dnstype,
            ttl,
            record["Rank"],
            record["Serial"],
            preference,
            port,
            priority,
            weight,
        )
        if tmp_record.getData() == raw_record:
            record_to_remove = raw_record
            break

    if not record_to_remove:
        LOG.warning("Record not found")
        return

    if len(dns_list) > 1:
        await ldap.bloodymodify(
            record_dn, {"dnsRecord": [(Change.DELETE.value, record_to_remove)]}
        )
    else:
        await ldap.bloodydelete(record_dn)

    LOG.info(f"Given record has been successfully removed from {name}")


async def genericAll(conn: ConnectionHandler, target: str, trustee: str):
    """
    Remove full control of trustee on target

    :param target: sAMAccountName, DN or SID of the target
    :param trustee: sAMAccountName, DN or SID of the trustee
    """
    ldap = await conn.getLdap()
    new_sd, _ = await utils.getSD(conn, target)
    if "s-1-" in trustee.lower():
        trustee_sid = trustee
    else:
        entry = None
        async for e in ldap.bloodysearch(trustee, attr=["objectSid"]):
            entry = e
            break
        trustee_sid = entry["objectSid"]
    utils.delRight(new_sd, trustee_sid)

    req_flags = badldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
        {"Flags": accesscontrol.DACL_SECURITY_INFORMATION}
    )
    controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

    await ldap.bloodymodify(
        target,
        {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
        controls,
    )

    LOG.info(f"{trustee} doesn't have GenericAll on {target} anymore")


async def groupMember(conn: ConnectionHandler, group: str, member: str):
    """
    Remove member (user, group, computer) from group

    :param group: sAMAccountName, DN or SID of the group
    :param member: sAMAccountName, DN or SID of the member
    """
    # This is equivalent to classic add member,
    # see [MS-ADTS] - 3.1.1.3.1.2.4 Alternative Forms of DNs
    # But <SID='sid'> also has the advantage of being compatible with foreign security principals,
    # see [MS-ADTS] - 3.1.1.5.3.3 Processing Specifics
    ldap = await conn.getLdap()
    if "s-1-" in member.lower():
        # We assume member is an SID
        member_transformed = f"<SID={member}>"
    else:
        member_transformed = await ldap.dnResolver(member)

    await ldap.bloodymodify(
        group, {"member": [(Change.DELETE.value, member_transformed)]}
    )
    LOG.info(f"{member} removed from {group}")


async def object(conn: ConnectionHandler, target: str):
    """
    Remove object (user, group, computer, organizational unit, etc)

    :param target: sAMAccountName, DN or SID of the target
    """
    ldap = await conn.getLdap()
    await ldap.bloodydelete(target)
    LOG.info(f"{target} has been removed")


async def rbcd(conn: ConnectionHandler, target: str, service: str):
    """
    Remove Resource Based Constraint Delegation for service on target

    :param target: sAMAccountName, DN or SID of the target
    :param service: sAMAccountName, DN or SID of the service account
    """
    ldap = await conn.getLdap()
    control_flag = 0
    new_sd, _ = await utils.getSD(
        conn, target, "msDS-AllowedToActOnBehalfOfOtherIdentity", control_flag
    )
    if "s-1-" in service.lower():
        service_sid = service
    else:
        entry = None
        async for e in ldap.bloodysearch(service, attr=["objectSid"]):
            entry = e
            break
        service_sid = entry["objectSid"]
    access_mask = accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
    utils.delRight(new_sd, service_sid, access_mask)

    attr_values = []
    if len(new_sd["Dacl"].aces) > 0:
        attr_values = new_sd.getData()
    await ldap.bloodymodify(
        target,
        {
            "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                (
                    Change.REPLACE.value,
                    attr_values,
                )
            ]
        },
    )

    LOG.info(f"{service} can't impersonate users on {target} anymore")


async def shadowCredentials(conn: ConnectionHandler, target: str, key: str = None):
    """
    Remove Key Credentials from target

    :param target: sAMAccountName, DN or SID of the target
    :param key: RSA key of Key Credentials to remove from the target, removes all if key not specified
    """
    ldap = await conn.getLdap()
    entry = None
    async for e in ldap.bloodysearch(target, attr=["msDS-KeyCredentialLink"], raw=True):
        entry = e
        break
    keyCreds = entry.get("msDS-KeyCredentialLink", [])
    newKeyCreds = []
    isFound = False
    for keyCred in keyCreds:
        key_raw = common.DNBinary(keyCred).value
        key_blob = cryptography.KEYCREDENTIALLINK_BLOB(key_raw)
        if key and key_blob.getKeyID() != binascii.unhexlify(key):
            newKeyCreds.append(keyCred.decode())
        else:
            isFound = True
            LOG.debug("Key to delete found")

    if not isFound:
        LOG.warning("No key found")
        return
       
    await ldap.bloodymodify(
        target, {"msDS-KeyCredentialLink": [(Change.REPLACE.value, newKeyCreds)]}
    )
    str_key = key if key else "All keys"
    LOG.info(f"{str_key} removed")


async def uac(conn: ConnectionHandler, target: str, f: list = None):
    """
    Remove property flags altering user/computer object behavior

    :param target: sAMAccountName, DN or SID of the target
    :param f: name of property flag to remove, can be called multiple times if multiple flags to remove (e.g -f LOCKOUT  -f ACCOUNTDISABLE)
    """
    ldap = await conn.getLdap()
    uac = 0
    for flag in f:
        uac |= accesscontrol.ACCOUNT_FLAGS[flag]

    try:
        entry = None
        async for e in ldap.bloodysearch(target, attr=["userAccountControl"], raw=True):
            entry = e
            break
        old_uac = entry["userAccountControl"][0]
    except IndexError as e:
        entry = None
        async for search_entry in ldap.bloodysearch(target, attr=["allowedAttributes"]):
            entry = search_entry
            break
        for allowed in entry["allowedAttributes"]:
            if "userAccountControl" in allowed:
                raise BloodyError(
                    "Current user doesn't have the right to read userAccountControl on"
                    f" {target}"
                ) from e
        raise BloodyError(f"{target} doesn't have userAccountControl attribute") from e

    uac = int(old_uac) & ~uac
    await ldap.bloodymodify(
        target, {"userAccountControl": [(Change.REPLACE.value, uac)]}
    )

    LOG.info(f"{f} property flags removed from {target}'s userAccountControl")
