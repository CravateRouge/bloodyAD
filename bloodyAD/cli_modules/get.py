from bloodyAD.formatters import formatters, ldaptypes, accesscontrol
from bloodyAD import utils
from bloodyAD.utils import LOG, getDefaultNamingContext
import json, logging
from functools import lru_cache
from typing import Literal
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
            res = ldap_conn.bloodysearch(
                container_dn,
                "(objectClass=dnsNode)",
                search_scope=ldap3.SUBTREE,
                attr=["dnsRecord", "dNSTombstoned"]
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


def membership(
    conn,
    target: str,
    no_recurse: bool = False
):
    """
    Retrieves SID and SAM Account Names of all groups a target belongs to

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param no_recurse: if set, doesn't retrieve groups where target isn't a direct member
    """
    # We fetch primaryGroupID, since this group is not reflected in memberOf
    # Additionally we get objectSid to have the domain sid 
    # it is helpful to resolve the primary group RID to a DN
    # Finally we add the special identity groups: Authenticated Users and Everyone
    
    filter = ""
    if no_recurse:
        entries = conn.ldap.bloodysearch(target, attr=["objectSid", "memberOf"])
        for entry in entries:
            if "attributes" not in entry:
                continue
            for group in entry["attributes"]["memberOf"]:
                filter += f"(distinguishedName={group})" 
        if not filter:
            LOG.warning("[!] No direct group membership found")
            return []
    else:
        # [MS-ADTS] 3.1.1.4.5.19 tokenGroups, tokenGroupsNoGCAcceptable
        attr = "tokenGroups"
        entries = conn.ldap.bloodysearch(target, attr=[attr])
        for entry in entries:
            if "attributes" not in entry:
                continue
            for groupSID in entry["attributes"][attr]:
                filter += f"(objectSID={groupSID})"
        if not filter:           
            LOG.warning("no GC Server available, the set of groups might be incomplete")
            attr = "tokenGroupsNoGCAcceptable"
            entries = conn.ldap.bloodysearch(target, attr=[attr])
            for entry in entries:
                if "attributes" not in entry:
                    continue
                for groupSID in entry["attributes"][attr]:
                    filter += f"(objectSID={groupSID})"
    entries = conn.ldap.bloodysearch(conn.ldap.domainNC, f"(|{filter})", search_scope=ldap3.SUBTREE, attr=["objectSID","sAMAccountName"])

    for entry in entries:
        if "attributes" not in entry:
            continue
        LOG.info(f"{entry['attributes']['sAMAccountName']}: {entry['attributes']['objectSID']}")
    return entries


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


def search(
    conn, 
    searchbase: str,
    filter: str = "(objectClass=*)",
    attr: str = "*",
):
    """
    Search in LDAP database

    :param searchbase: DN of the parent object
    :param filter: filter to apply to the LDAP search (see Microsoft LDAP filter syntax)
    :param attr: attributes to retrieve separated by a comma
    """
    
    entries = conn.ldap.bloodysearch(
        searchbase,
        filter,
        search_scope=ldap3.SUBTREE,
        attr=attr.split(","),
        generator=True
    )
    
    LOG.info(conn.getLdapConnection().response_to_json())

    return entries


def writable(
    conn,
    otype: Literal["ALL", "OU", "USER", "COMPUTER", "GROUP", "DOMAIN", "GPO"] = "ALL",
    right: Literal["ALL", "WRITE", "CHILD"] = "ALL",
    detail: bool = False,
    #partition: Literal["DOMAIN", "DNS", "ALL"] = "DOMAIN"
):
    """
    Retrieves objects writable by client

    :param otype: type of writable object to retrieve
    :param right: type of right to search
    :param detail: if set, displays attributes/object types you can write/create for the object
    """
    #:param partition: directory partition a.k.a naming context to explore

    if otype == "ALL":
        objectClass = "*"
    elif otype == "OU":
        objectClass = "container"
    elif otype == "GPO":
        objectClass = "groupPolicyContainer"
    else:
        objectClass = otype

    attr = {}
    genericReturn = (lambda a: [b for b in a]) if detail else (lambda a: [])
    if right == "WRITE" or right == "ALL":
        attr["allowedAttributesEffective"] = {"lambda":genericReturn, "right":"WRITE"}
        def testSDRights(a):
            r = []
            if a & 3:
                r.append("OWNER")
            if a & 4:
                r.append("DACL")
            if a & 8:
                r.append("SACL")
            return r
        attr["sDRightsEffective"] = {"lambda":testSDRights, "right":"WRITE"}
    if right == "CREATE" or right == "ALL":
        attr["allowedChildClassesEffective"] = {"lambda":genericReturn, "right":"CREATE"}

    searchbases = []
    #if partition == "DOMAIN":
    searchbases.append(conn.ldap.domainNC)
    # elif partition == "DNS":
    #     searchbases.append(conn.ldap.applicationNCs) # A definir https://learn.microsoft.com/en-us/windows/win32/ad/enumerating-application-directory-partitions-in-a-forest
    # else:
    #     searchbases.append(conn.ldap.NCs) # A definir
    res = {}
    for searchbase in searchbases:
        for entry in conn.ldap.bloodysearch(
            searchbase,
            f"(objectClass={objectClass})",
            search_scope=ldap3.SUBTREE,
            attr=attr.keys(),
            generator=True
        ):
            for a,lr in attr.items():
                if "attributes" in entry and entry["attributes"][a]:
                    if entry["dn"] not in res:
                        res[entry["dn"]] = {}
                    res[entry["dn"]][lr["right"]] = lr["lambda"](entry["attributes"][a])
    
    sres = ""
    for dn in res:
        if sres:
            sres += '\n'
        sres += "dn: " + dn + '\n'
        for r in res[dn]:
            if not res[dn][r]:
                sres += "right: " + r + '\n'
            for a in res[dn][r]:
                sres += a + ': ' + r + '\n'
    LOG.info(sres)

    return res

                