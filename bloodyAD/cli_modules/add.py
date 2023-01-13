from typing import Literal
from bloodyAD.utils import LOG, getDefaultNamingContext, search
from bloodyAD.exceptions import BloodyError
from bloodyAD.formatters.dns import dnsRecord
from ldap3.core.exceptions import (
    LDAPEntryAlreadyExistsResult,
    LDAPAttributeOrValueExistsResult,
)
from ldap3 import MODIFY_ADD

# Credits to Kevin Robertson and his script Invoke-DNSUpdate.ps1 from the Powermad framework
def domainDNSRecord(
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
    ldap_conn = conn.getLdapConnection()

    # DNS_RPC_RECORD - section 2.2.2.2.5
    # RANK_ZONE - The record comes from an authoritative zone
    rank = 0xF0

    naming_context = "," + getDefaultNamingContext(ldap_conn)
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

    if forest:
        zone_type = "ForestDnsZones"
    else:
        zone_type = "DomainDnsZones"

    zone_dn = f",DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}"
    record_dn = f"DC={name}{zone_dn}"

    serial = None
    for dns_record in search(conn, f"DC=@{zone_dn}", attr="dnsRecord")[0]["attributes"][
        "dnsRecord"
    ]:
        if dns_record.get("Type") == "SOA":
            serial = dns_record["Data"]["SerialNo"]
            break

    dns_record = dnsRecord()
    dns_record.fromDict(
        data, dnstype, ttl, rank, serial, preference, port, priority, weight
    )
    record_attr = {
        "objectClass": ["top", "dnsNode"],
        "dnsRecord": dns_record.getData(),
        "dNSTombstoned": False,
    }

    try:
        ldap_conn.add(record_dn, attributes=record_attr)
        success_log = f"[+] {name} has been successfully added"
    except LDAPEntryAlreadyExistsResult:
        try:
            ldap_conn.modify(
                record_dn, {"dnsRecord": (MODIFY_ADD, record_attr["dnsRecord"])}
            )
            success_log = f"[+] {name} has been successfully updated"
        except LDAPAttributeOrValueExistsResult:
            LOG.warning(f"[!] {name} has already a record of this type")
            LOG.warning("[!] Record not updated")
            return

    if ldap_conn.result["description"] == "success":
        LOG.info(success_log)
    else:
        raise BloodyError(ldap_conn.result["description"])
