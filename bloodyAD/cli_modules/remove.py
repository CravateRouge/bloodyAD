from typing import Literal
from bloodyAD.utils import LOG, getDefaultNamingContext, search
from bloodyAD.exceptions import BloodyError
from bloodyAD.formatters.dns import dnsRecord
from ldap3 import MODIFY_DELETE


def domainDNSRecord(
    conn,
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
    This function removes a DNS record of an AD environment.

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
    ldap_conn = conn.getLdapConnection()

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

    record_to_remove = None
    for raw_record in search(conn, record_dn, attr="dnsRecord")[0]["raw_attributes"][
        "dnsRecord"
    ]:
        record = dnsRecord(raw_record)
        tmp_record = dnsRecord()

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
        LOG.warning("[!] Record not found")
        return

    ldap_conn.modify(record_dn, {"dnsRecord": (MODIFY_DELETE, record_to_remove)})

    if ldap_conn.result["description"] == "success":
        LOG.info(f"[-] Given record has been successfully removed from {name}")
    else:
        raise BloodyError(ldap_conn.result["description"])
