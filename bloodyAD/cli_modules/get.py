from bloodyAD.utils import LOG, getDefaultNamingContext, search
import ldap3
from ldap3.core.exceptions import LDAPNoSuchObjectResult


def domainDNSRecord(
    conn,
    zone: str = None,
    include_tombstoned: bool = False,
    include_rootservers: bool = False,
    no_legacy: bool = False,
    no_forest: bool = False,
    no_domain: bool = False,
):
    """
    Prints DNS records of the Active Directory readable by the user

    :param zone: if set, prints only records in this zone
    :param include_tombstoned: if set, includes tombstoned records
    :param include_rootservers: if set, includes DNS root servers
    :param no_legacy: if set, excludes records in main partition
    :param no_forest: if set, excludes records in forest partition
    :param no_domain: if set, excludes records in domain partition
    """
    ldap_conn = conn.getLdapConnection()

    naming_context = getDefaultNamingContext(ldap_conn)
    containers = []
    container = ""
    if not no_legacy:
        container = naming_context
        if zone:
            container = f"DC={zone},CN=MicrosoftDNS,CN=System,{container}"
        containers.append(container)
    if not no_forest:
        container = f"DC=ForestDnsZones,{naming_context}"
        if zone:
            container = f"DC={zone},CN=MicrosoftDNS,{container}"
        containers.append(container)
    if not no_domain:
        container = f"DC=DomainDnsZones,{naming_context}"
        if zone:
            container = f"DC={zone},CN=MicrosoftDNS,{container}"
        containers.append(container)

    printable_entries = ""
    for container_dn in containers:
        res = None
        try:
            res = search(
                conn,
                container_dn,
                ldap_filter="(objectClass=dnsNode)",
                attr=["dnsRecord", "dNSTombstoned"],
                search_scope=ldap3.SUBTREE,
            )
        except LDAPNoSuchObjectResult:
            continue

        for entry in res:
            # Ignore searchResRef entry
            if entry["type"] == "searchResRef":
                continue
            if entry["attributes"]["dNSTombstoned"] and not include_tombstoned:
                continue
            dn = entry["dn"][3:]
            hostname = ""
            skip = False
            for level in dn.split(",CN=")[0].split(",DC="):
                if level == "RootDNSServers":
                    skip = not include_rootservers
                    break
                if level == "@":
                    continue
                hostname += level + "."
            # Ignore this entry
            if skip:
                continue

            if not hostname:
                hostname = "."

            for record in entry["attributes"]["dnsRecord"]:
                printable_entries += hostname
                record_data = None
                try:
                    if record["Type"] in ["A", "AAAA", "NS", "CNAME", "PTR", "TXT"]:
                        record_data = [record["Data"], record["Type"]]
                    elif record["Type"] == "MX":
                        record_data = [record["Data"]["Name"], record["Type"]]
                    elif record["Type"] == "SRV":
                        record_data = [
                            f"{record['Data']['Target']}:{record['Data']['Port']}",
                            record["Type"],
                        ]
                    elif record["Type"] == "SOA":
                        record_data = [
                            record["Data"]["PrimaryServer"],
                            record["Data"]["zoneAdminEmail"],
                            record["Type"],
                        ]
                    else:
                        LOG.warn(
                            "[!] Record type: "
                            + record["Type"]
                            + " not supported yet! Raise an issue if you think it"
                            " matters"
                        )
                        continue

                except KeyError:
                    LOG.error("[-] KeyError for record: " + record)
                    continue

                for data in record_data:
                    printable_entries += f" :-> {data}"
                printable_entries += "\n"

    LOG.info(printable_entries)
