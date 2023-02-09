from bloodyAD import formatters
from bloodyAD.utils import LOG, getDefaultNamingContext, search, getGroupMembership, getOrganizationalUnits, getObjectSID
import ldap3
from ldap3.core.exceptions import LDAPNoSuchObjectResult
from ldap3.protocol.formatters.formatters import format_sid
import json
import base64


def object(
    conn,
    cn: str,
    attr: str = "*",
    fetchSD: bool = False
):
    """
    Fetch LDAP attributes for the cn provided

    :param cn: common name of the object for which the attributes will be fetched
    :param attr: attribute name to fetch, default to fetch all the attributes
    :param fetchSD: If True, security descriptor of the object will be fetched and parsed, otherwise this attribute is filtered out (default to False)
    """
    control_flag = formatters.accesscontrol.OWNER_SECURITY_INFORMATION
    if fetchSD:
        control_flag += (
            formatters.accesscontrol.GROUP_SECURITY_INFORMATION +
            formatters.accesscontrol.DACL_SECURITY_INFORMATION
        )
    data = search(conn, cn, attr=attr, control_flag=control_flag)
    data_json = json.dumps(data[0]["attributes"], indent=4, sort_keys=True)
    LOG.info(data_json)
    return data_json


def membership(
    conn,
    identity: str,
    recurse: bool = True
):
    """
    Fetch all the groups a user or group belongs to, recursively

    :param identity: cn, sid, guid or samAccountName of the target identity
    :param recurse: list groups recursively
    """
    groups = getGroupMembership(conn, identity, recurse)
    groups_json = json.dumps(sorted(list(groups)), indent=4, sort_keys=True)
    LOG.info(groups_json)
    return groups_json


def writableOU(
    conn, 
    identity: str,
    page_size: int = 200
):
    """
    Return all the Organizational Units that can be used by the identity provided to create computer

    :param identity: cn, sid, guid or samAccountName of the target identity
    :param page_size: number of OUs fetched with each request (default 200)
    """

    # Fetch group membership
    groups = getGroupMembership(conn, identity, recurse=True)
    groups_sid = [format_sid(getObjectSID(conn, group)) for group in groups]
    groups_sid.append("S-1-5-11")
    groups_sid.append("S-1-1-0")

    formatters.disable_nt_security_descriptor_parsing = True

    # Walk the OU hierarchy
    attr = ["ntSecurityDescriptor", "distinguishedName"]
    vulnerable_ous = set()
    interesting_perms = ["FULL_CONTROL", "GENERIC_ALL", "GENERIC_WRITE", "ADS_RIGHT_DS_CREATE_CHILD"]
    for ou in getOrganizationalUnits(conn, attributes=attr, page_size=page_size):

        sd_b64 = ou["attributes"]["nTSecurityDescriptor"]["encoded"]
        sd_bytes = base64.b64decode(sd_b64)
        sd = formatters.ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)

        ownerSid = sd["OwnerSid"].formatCanonical()
        if ownerSid in groups_sid:
            LOG.info(f"owner of {ou['attributes']['distinguishedName']}")
            continue

        for ace in sd["Dacl"]["Data"]:
            aceSid = ace["Ace"]["Sid"].formatCanonical()
            if aceSid in groups_sid:
                aceType = ace["TypeName"]
                if aceType == 'ACCESS_ALLOWED_ACE':
                    aceMask = formatters.accesscontrol.decodeAccessMask(ace["Ace"]["Mask"])
                    for perm in aceMask:
                        if perm in interesting_perms:
                            LOG.info(f"{perm} on {ou['attributes']['distinguishedName']}")


    # TODO: do the same with the container that are not OUs
    formatters.disable_nt_security_descriptor_parsing = False
    return vulnerable_ous

    

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
