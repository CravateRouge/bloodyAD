from bloodyAD import utils, asciitree
from bloodyAD.exceptions import LOG
from bloodyAD.network.ldap import Scope
from bloodyAD.exceptions import NoResultError
from msldap.commons.exceptions import LDAPSearchException
from typing import Literal
import re, asyncio


def children(conn, target: str = "DOMAIN", otype: str = "*", direct: bool = False):
    """
    List children for a given target object

    :param target: sAMAccountName, DN or SID of the target
    :param otype: special keyword "useronly" or objectClass of objects to fetch e.g. user, computer, group, trustedDomain, organizationalUnit, container, groupPolicyContainer, msDS-GroupManagedServiceAccount, etc
    :param direct: Fetch only direct children of target
    """
    if target == "DOMAIN":
        target = conn.ldap.domainNC
    scope = Scope.LEVEL if direct else Scope.SUBTREE
    if otype == "useronly":
        otype_filter = "sAMAccountType=805306368"
    else:
        otype_filter = f"objectClass={otype}"
    return conn.ldap.bloodysearch(
        target,
        f"(&({otype_filter})(!(distinguishedName={target})))",
        search_scope=scope,
        attr=["distinguishedName"],
    )


def dnsDump(conn, zone: str = None, no_detail: bool = False, transitive: bool = False):
    """
    Retrieve DNS records of the Active Directory readable/listable by the user

    :param zone: if set, prints only records in this zone
    :param no_detail: if set doesn't include system records such as _ldap, _kerberos, @, etc
    :param transitive: if set, try to fetch dns records in AD trusts (you should start from a DC of your user domain to have exhaustive results)
    """

    def domainDnsDump(conn, zone=None, no_detail=False):
        entries = None
        filter = "(|(objectClass=dnsNode)(objectClass=dnsZone))"
        prefix_blacklist = [
            "gc",
            "_gc.*",
            "_kerberos.*",
            "_kpasswd.*",
            "_ldap.*",
            "_msdcs",
            "@",
            "DomainDnsZones",
            "ForestDnsZones",
        ]
        suffix_blacklist = ["RootDNSServers", "..TrustAnchors"]

        if no_detail:
            prefix_filter = ""
            for prefix in prefix_blacklist:
                prefix_filter += f"(!(name={prefix}))"
            filter = f"(&{filter}{prefix_filter})"

        dnsZones = []
        for nc in conn.ldap.appNCs + [conn.ldap.domainNC]:
            try:
                entries = conn.ldap.bloodysearch(
                    nc,
                    filter,
                    search_scope=Scope.SUBTREE,
                    attr=["dnsRecord", "name", "objectClass"],
                )
                for entry in entries:
                    domain_suffix = entry["distinguishedName"].split(",")[1]
                    domain_suffix = domain_suffix.split("=")[1]

                    # RootDNSServers and ..TrustAnchors are system records not interesting for offensive normally
                    if domain_suffix in suffix_blacklist:
                        continue

                    if zone and zone not in domain_suffix:
                        continue

                    # We keep dnsZone to list their children later
                    # Useful if we have list_child on it but no read_prop on the child record
                    if "dnsZone" in entry["objectClass"]:
                        dnsZones.append(entry["distinguishedName"])
                        if entry["name"] not in suffix_blacklist:
                            yield {"zoneName": entry["name"]}
                        continue

                    domain_name = entry["name"]

                    if domain_name == "@":  # @ is for dnsZone info
                        domain_name = domain_suffix
                    else:  # even for reverse lookup (X.X.X.X.in-addr.arpa), domain suffix should be the parent name?
                        if (
                            domain_name[-1] != "."
                        ):  # Then it's probably not a fqdn, suffix needed
                            domain_name = domain_name + "." + domain_suffix

                    ip_addr = domain_name.split(".in-addr.arpa")
                    if len(ip_addr) > 1:
                        decimals = ip_addr[0].split(".")
                        decimals.reverse()
                        while len(decimals) < 4:
                            decimals.append("0")
                        domain_name = ".".join(decimals)

                    yield_entry = {"recordName": domain_name}

                    for record in entry.get("dnsRecord", []):
                        try:
                            if record["Type"] not in yield_entry:
                                yield_entry[record["Type"]] = []
                            if record["Type"] in [
                                "A",
                                "AAAA",
                                "NS",
                                "CNAME",
                                "PTR",
                                "TXT",
                            ]:
                                yield_entry[record["Type"]].append(record["Data"])
                            elif record["Type"] == "MX":
                                yield_entry[record["Type"]].append(
                                    record["Data"]["Name"]
                                )
                            elif record["Type"] == "SRV":
                                yield_entry[record["Type"]].append(
                                    f"{record['Data']['Target']}:{record['Data']['Port']}"
                                )
                            elif record["Type"] == "SOA":
                                yield_entry[record["Type"]].append(
                                    {
                                        "PrimaryServer": record["Data"][
                                            "PrimaryServer"
                                        ],
                                        "zoneAdminEmail": record["Data"][
                                            "zoneAdminEmail"
                                        ].replace(".", "@", 1),
                                    }
                                )
                        except KeyError:
                            LOG.error("[-] KeyError for record: " + record)
                            continue

                    yield yield_entry
            except (NoResultError, LDAPSearchException) as e:
                if type(e) is NoResultError:
                    LOG.warning(f"[!] No readable record found in {nc}")
                else:
                    LOG.warning(f"[!] {nc} couldn't be read on {conn.conf.host}")
                continue
        # List record names if we have list child right on dnsZone or MicrosoftDNS container but no READ_PROP on record object
        for nc in conn.ldap.appNCs:
            dnsZones.append(f"CN=MicrosoftDNS,{nc}")
        dnsZones.append(f"CN=MicrosoftDNS,CN=System,{conn.ldap.domainNC}")
        for searchbase in dnsZones:
            try:
                entries = conn.ldap.bloodysearch(
                    searchbase,
                    "(objectClass=*)",
                    search_scope=Scope.SUBTREE,
                    attr=["objectClass"],
                )
                for entry in entries:
                    # If we can get objectClass it means we have a READ_PROP on the record object so we already found it before
                    if (
                        entry.get("objectClass")
                        or entry["distinguishedName"] == searchbase
                    ):
                        continue

                    domain_parts = entry["distinguishedName"].split(",")
                    domain_suffix = domain_parts[1].split("=")[1]

                    domain_name = domain_parts[0].split("=")[1]
                    if no_detail and re.match("|".join(prefix_blacklist), domain_name):
                        continue

                    if domain_name[-1] != "." and domain_suffix != "MicrosoftDNS":
                        # Then it's probably not a fqdn, suffix certainly needed
                        domain_name = f"{domain_name}.{domain_suffix}"

                    ip_addr = domain_name.split(".in-addr.arpa")
                    if len(ip_addr) > 1:
                        decimals = ip_addr[0].split(".")
                        decimals.reverse()
                        while len(decimals) < 4:
                            decimals.append("0")
                        domain_name = ".".join(decimals)

                    yield {"recordName": domain_name}
            except (NoResultError, LDAPSearchException) as e:
                if type(e) is NoResultError:
                    LOG.warning(f"[!] No listable record found in {nc}")
                else:
                    LOG.warning(f"[!] {nc} couldn't be read on {conn.conf.host}")
                continue

    # Used to avoid duplicate entries if there is the same record in multiple partitions
    record_dict = {}
    record_entries = []
    if transitive:
        trustmap = conn.ldap.getTrustMap()
        for trust in trustmap.values():
            if "conn" in trust:
                record_entries.append(domainDnsDump(trust["conn"], zone, no_detail))
    else:
        record_entries.append(domainDnsDump(conn, zone, no_detail))

    basic_records = []
    for records in record_entries:
        for r in records:
            keyName = "recordName" if "recordName" in r else "zoneName"
            # If it's a record with only the record name returns it later and only if we didn't find another record with more info
            if len(r) == 1 and keyName == "recordName":
                basic_records.append(r)
                continue
            yield_r = {}

            rname = r[keyName]
            if rname in record_dict:
                for r_type in r:
                    if r_type == keyName:
                        continue
                    if record_dict[rname].get(r_type):
                        if r[r_type] in record_dict[rname][r_type]:
                            continue
                    else:
                        record_dict[rname][r_type] = []
                    yield_r[r_type] = r[r_type]
                    record_dict[rname][r_type].append(r[r_type])
                if not yield_r:
                    continue
            else:
                yield_r = r
                record_dict[rname] = {}
                for k, v in r.items():
                    record_dict[rname][k] = [v]

            yield_r[keyName] = rname

            yield yield_r

    for basic_r in basic_records:
        if basic_r["recordName"] in record_dict:
            continue
        yield basic_r


def membership(conn, target: str, no_recurse: bool = False):
    """
    Retrieve SID and SAM Account Names of all groups a target belongs to

    :param target: sAMAccountName, DN or SID of the target
    :param no_recurse: if set, doesn't retrieve groups where target isn't a direct member
    """
    ldap_filter = ""
    if no_recurse:
        entries = conn.ldap.bloodysearch(target, attr=["objectSid", "memberOf"])
        for entry in entries:
            for group in entry.get("memberOf", []):
                ldap_filter += f"(distinguishedName={group})"
        if not ldap_filter:
            LOG.warning("[!] No direct group membership found")
            return []
    else:
        # [MS-ADTS] 3.1.1.4.5.19 tokenGroups, tokenGroupsNoGCAcceptable
        attr = "tokenGroups"
        entries = conn.ldap.bloodysearch(target, attr=[attr])
        for entry in entries:
            try:
                for groupSID in entry[attr]:
                    ldap_filter += f"(objectSID={groupSID})"
            except KeyError:
                LOG.warning("[!] No membership found")
                return []
        if not ldap_filter:
            LOG.warning("no GC Server available, the set of groups might be incomplete")
            attr = "tokenGroupsNoGCAcceptable"
            entries = conn.ldap.bloodysearch(target, attr=[attr])
            for entry in entries:
                for groupSID in entry[attr]:
                    ldap_filter += f"(objectSID={groupSID})"

    entries = conn.ldap.bloodysearch(
        conn.ldap.domainNC,
        f"(|{ldap_filter})",
        search_scope=Scope.SUBTREE,
        attr=["objectSID", "sAMAccountName"],
    )
    return entries


def trusts(conn, transitive: bool = False):
    """
    Display trusts in an ascii tree starting from the DC domain as tree root. A->B means A can auth on B and A-<B means B can auth on A, A-<>B means bidirectional

    :param transitive: Try to fetch transitive trusts (you should start from a dc of your user domain to have more complete results)
    """

    trust_dict = asyncio.get_event_loop().run_until_complete(
        conn.ldap.getTrusts(transitive, conn.conf.dns)
    )

    # Get the host domain as root for the trust tree
    trust_root_domain = conn.ldap.dc_domain
    if trust_dict:
        tree = {}
        asciitree.branchFactory({":" + trust_root_domain: tree}, [], trust_dict)
        tree_printer = asciitree.LeftAligned()
        print(tree_printer({trust_root_domain: tree}))


def object(
    conn,
    target: str,
    attr: str = "*",
    resolve_sd: bool = False,
    raw: bool = False,
    transitive: bool = False,
):
    """
    Retrieve LDAP attributes for the target object provided, binary data will be outputted in base64

    :param target: sAMAccountName, DN or SID of the target (if you give an empty string "" prints rootDSE)
    :param attr: attributes to retrieve separated by a comma, retrieves all the attributes by default
    :param resolve_sd: if set, permissions linked to a security descriptor will be resolved (see bloodyAD github wiki/Access-Control for more information)
    :param raw: if set, will return attributes as sent by the server without any formatting, binary data will be outputted in base64
    :param transitive: if set with "--resolve-sd", will try to resolve foreign SID by reaching trusts
    """
    attributesSD = [
        "nTSecurityDescriptor",
        "msDS-GroupMSAMembership",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
    conn.conf.transitive = transitive
    entries = conn.ldap.bloodysearch(target, attr=attr.split(","), raw=raw)
    rendered_entries = utils.renderSearchResult(entries)
    if resolve_sd and not raw:
        for entry in rendered_entries:
            for attrSD in attributesSD:
                if attrSD in entry:
                    e = entry[attrSD]
                    if not isinstance(e, list):
                        entry[attrSD] = utils.renderSD(e, conn)
                    else:
                        entry[attrSD] = [utils.renderSD(sd, conn) for sd in e]
            yield entry
    else:
        yield from rendered_entries


def search(
    conn,
    base: str = "DOMAIN",
    filter: str = "(objectClass=*)",
    attr: str = "*",
    resolve_sd: bool = False,
    raw: bool = False,
    transitive: bool = False,
    c: list = [],
):
    """
    Search in LDAP database, binary data will be outputted in base64

    :param base: DN of the parent object
    :param filter: filter to apply to the LDAP search (see Microsoft LDAP filter syntax)
    :param attr: attributes to retrieve separated by a comma
    :param resolve_sd: if set, permissions linked to a security descriptor will be resolved (see bloodyAD github wiki/Access-Control for more information)
    :param raw: if set, will return attributes as sent by the server without any formatting, binary data will be outputed in base64
    :param transitive: if set with "--resolve-sd", will try to resolve foreign SID by reaching trusts
    :param c: if set, will use the controls for extended search operations, e.g. "-c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065" to display tombstoned, deleted and recycled objects and their linked attributes
    """
    attributesSD = [
        "nTSecurityDescriptor",
        "msDS-GroupMSAMembership",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
    conn.conf.transitive = transitive
    if base == "DOMAIN":
        base = conn.ldap.domainNC
    # RFC2251 4.1.12 Controls
    # control ::= (controlType, criticality, controlValue)
    controls = [(oid,True,None) for oid in c]
    entries = conn.ldap.bloodysearch(
        base, filter, search_scope=Scope.SUBTREE, attr=attr.split(","), raw=raw, controls=controls
    )
    rendered_entries = utils.renderSearchResult(entries)
    if resolve_sd and not raw:
        for entry in rendered_entries:
            for attrSD in attributesSD:
                if attrSD in entry:
                    e = entry[attrSD]
                    if not isinstance(e, list):
                        entry[attrSD] = utils.renderSD(e, conn)
                    else:
                        entry[attrSD] = [utils.renderSD(sd, conn) for sd in e]
            yield entry
    else:
        yield from rendered_entries


# TODO: Search writable for application partitions too?
def writable(
    conn,
    otype: Literal["ALL", "OU", "USER", "COMPUTER", "GROUP", "DOMAIN", "GPO"] = "ALL",
    right: Literal["ALL", "WRITE", "CHILD"] = "ALL",
    detail: bool = False,
    include_del: bool = False,
    # partition: Literal["DOMAIN", "DNS", "ALL"] = "DOMAIN"
):
    """
    Retrieve objects writable by client

    :param otype: type of writable object to retrieve
    :param right: type of right to search
    :param detail: if set, displays attributes/object types you can write/create for the object
    :param include_del: if set, include deleted objects
    """
    # :param partition: directory partition a.k.a naming context to explore

    ldap_filter = ""
    if otype == "USER":
        ldap_filter = "(sAMAccountType=805306368)"
    elif otype == "OU":
        ldap_filter = "(|(objectClass=container)(objectClass=organizationalUnit))"
    else:
        if otype == "ALL":
            objectClass = "*"
        elif otype == "GPO":
            objectClass = "groupPolicyContainer"
        else:
            objectClass = otype
        ldap_filter = f"(objectClass={objectClass})"

    attr_params = {}
    genericReturn = (
        (lambda a: [b for b in a])
        if detail
        else (lambda a: ["permission"] if a else [])
    )
    if right == "WRITE" or right == "ALL":
        attr_params["allowedAttributesEffective"] = {
            "lambda": genericReturn,
            "right": "WRITE",
        }

        def testSDRights(a):  # Mask defined in MS-ADTS for allowedAttributesEffective
            r = []
            if not a:
                return r
            if a & 3:
                r.append("OWNER")
            if a & 4:
                r.append("DACL")
            if a & 8:
                r.append("SACL")
            return r

        attr_params["sDRightsEffective"] = {"lambda": testSDRights, "right": "WRITE"}
    if right == "CHILD" or right == "ALL":
        attr_params["allowedChildClassesEffective"] = {
            "lambda": genericReturn,
            "right": "CREATE_CHILD",
        }
    
    controls = None
    if include_del:
        controls = [("1.2.840.113556.1.4.417", True, None),("1.2.840.113556.1.4.2065", True, None)]

    searchbases = []
    # if partition == "DOMAIN":
    searchbases.append(conn.ldap.domainNC)
    # elif partition == "DNS":
    #     searchbases.append(conn.ldap.applicationNCs) # A definir https://learn.microsoft.com/en-us/windows/win32/ad/enumerating-application-directory-partitions-in-a-forest
    # else:
    #     searchbases.append(conn.ldap.NCs) # A definir
    right_entry = {}
    for searchbase in searchbases:
        for entry in conn.ldap.bloodysearch(
            searchbase, ldap_filter, search_scope=Scope.SUBTREE, attr=attr_params.keys(), controls=controls
        ):
            for attr_name in entry:
                if attr_name not in attr_params:
                    continue
                key_names = attr_params[attr_name]["lambda"](entry[attr_name])
                for name in key_names:
                    if name == "distinguishedName":
                        name = "dn"
                    if name not in right_entry:
                        right_entry[name] = []
                    right_entry[name].append(attr_params[attr_name]["right"])

            if right_entry:
                yield {
                    **{"distinguishedName": entry["distinguishedName"]},
                    **right_entry,
                }
                right_entry = {}
