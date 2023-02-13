from bloodyAD.formatters import formatters, ldaptypes, accesscontrol
from bloodyAD.utils import LOG, getDefaultNamingContext, search, getOrganizationalUnits, getObjectSID, resolvDN
import json, logging
from functools import lru_cache
import ldap3
from ldap3.core.exceptions import LDAPNoSuchObjectResult
from ldap3.protocol.formatters.formatters import format_sid


def dnsRecord(
    conn,
    zone: str = None,
    include_tombstoned: bool = False,
    include_rootservers: bool = False,
    no_legacy: bool = False,
    no_forest: bool = False,
    no_domain: bool = False,
):
    """
    Retrieves DNS records of the Active Directory readable by the user

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
    record_list = []
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
                        LOG.warn("[!] Record type: " + record["Type"] + " not supported yet! Raise an issue if you think it matters")
                        continue

                except KeyError:
                    LOG.error("[-] KeyError for record: " + record)
                    continue

                for data in record_data:
                    printable_entries += f" :-> {data}"
                printable_entries += "\n"
                record_list.append([hostname, record_data])

    LOG.info(printable_entries)
    return record_list


@lru_cache
def membership(
    conn,
    target: str,
    no_recurse: bool = False
):
    """
    Retrieves all groups an object belongs to

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param no_recurse: list groups recursively
    """
    # We fetch primaryGroupID, since this group is not reflected in memberOf
    # Additionally we get objectSid to have the domain sid it is helpfuf
    # to resolv the primary group RID to a DN
    # Finally we had the special identity groups: Authenticated Users and Everyone

    data = search(conn, target, attr=["objectSid", "memberOf", "primaryGroupID"])
    data = data[0]["attributes"]
    groups = data["memberOf"]

    if data["primaryGroupID"]:
        domain_sid = "-".join(data["objectSid"].split("-")[:-1])
        primary_group_sid = domain_sid + "-" + str(data["primaryGroupID"])
        ldap_conn = conn.getLdapConnection()
        primary_group_dn = resolvDN(ldap_conn, primary_group_sid)
        groups.append(primary_group_dn)

    found_groups = set(groups)
    if not no_recurse:
        for group in groups:
            new_group = membership(conn, group, no_recurse)
            found_groups.update(new_group)

    groups_json = json.dumps(sorted(list(found_groups)), indent=4, sort_keys=True)
    LOG.info(groups_json)

    return found_groups


def object(
    conn,
    target: str,
    attr: str = "*",
    resolve_sd: bool = False,
    raw: bool = False
):
    """
    Retrieves LDAP attributes for the target object provided

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param attr: name of the attribute to retrieve, retrieves all the attributes by default
    :param resolve_sd: if set, permissions linked to a security descriptor will be resolved !!resolving can take some time!!
    :param raw: if set, will return attributes as sent by the server without any formatting, binary data will be outputed in base64
    """

    old_resolving = formatters.RESOLVING
    if resolve_sd:
        formatters.RESOLVING = True
    
    object_res = search(conn, target, attr=attr)
    formatters.RESOLVING = old_resolving

    if raw:
        object_attributes = object_res[0]["raw_attributes"]
    else:
        # We call response_to_json because it automatically converts
        # non printable objects into JSON
        object_json = conn.getLdapConnection().response_to_json()
        # And then we remove the "entries" container unnecessary for one object/entry
        object_attributes = json.loads(object_json)["entries"][0]["attributes"]
        
    printable_object = json.dumps(object_attributes, indent=4, sort_keys=True)
    LOG.info(printable_object)

    return object_attributes


def writableOU(
    conn, 
    target: str,
    page_size: int = 1000
):
    """
    Retrieves Organizational Units writable by target

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param page_size: number of OUs to fetch in each request
    """

    # Fetch group membership
    LOG.setLevel(logging.WARNING)
    groups = membership(conn, target)
    LOG.setLevel(logging.INFO)

    groups_sid = [format_sid(getObjectSID(conn, group)) for group in groups]
    groups_sid.append("S-1-5-11")
    groups_sid.append("S-1-1-0")

    # Walk the OU hierarchy
    attr = ["ntSecurityDescriptor", "distinguishedName"]
    vulnerable_ous = set()
    interesting_perms = ["FULL_CONTROL", "GENERIC_ALL", "GENERIC_WRITE", "ADS_RIGHT_DS_CREATE_CHILD"]
    for ou in getOrganizationalUnits(conn, attributes=attr, page_size=page_size):

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=ou["raw_attributes"]["nTSecurityDescriptor"][0])

        ownerSid = sd["OwnerSid"].formatCanonical()
        if ownerSid in groups_sid:
            LOG.info(f"owner of {ou['attributes']['distinguishedName']}")
            vulnerable_ous.update(ou['attributes']['distinguishedName'])
            continue

        for ace in sd["Dacl"]["Data"]:
            aceSid = ace["Ace"]["Sid"].formatCanonical()
            if aceSid in groups_sid:
                aceType = ace["TypeName"]
                if aceType == 'ACCESS_ALLOWED_ACE':
                    aceMask = accesscontrol.decodeAccessMask(ace["Ace"]["Mask"])
                    for perm in aceMask:
                        if perm in interesting_perms:
                            LOG.info(f"{perm} on {ou['attributes']['distinguishedName']}")
                            vulnerable_ous.update(ou['attributes']['distinguishedName'])

    return vulnerable_ous