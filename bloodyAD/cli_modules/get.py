from bloodyAD import utils, asciitree
from bloodyAD.utils import LOG
from bloodyAD.network.ldap import Scope
from bloodyAD.exceptions import NoResultError
from bloodyAD.formatters import common
from msldap.commons.exceptions import LDAPSearchException
from dns import resolver
from typing import Literal
import re


def children(conn, target: str = "DOMAIN", otype: str = "*", direct: bool = False):
    """
    List children for a given target object

    :param target: sAMAccountName, DN, GUID or SID of the target
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


# TODO: Fetch records from Global Catalog and also other partitions stored on other DC if possible
def dnsDump(conn, zone: str = None, no_detail: bool = False):
    """
    Retrieve DNS records of the Active Directory readable/listable by the user

    :param zone: if set, prints only records in this zone
    :param no_detail: if set doesn't include system records such as _ldap, _kerberos, @, etc
    """
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
        except (NoResultError, LDAPSearchException):
            continue

        domain_set = set()
        for entry in entries:
            domain_suffix = entry["distinguishedName"].split(",")[1]
            domain_suffix = domain_suffix.split("=")[1]

            # RootDNSServers and ..TrustAnchors are system records not interesting for offensive normally
            if domain_suffix == "RootDNSServers" or domain_suffix == "..TrustAnchors":
                continue

            if zone and zone not in domain_suffix:
                continue

            # We keep dnsZone to list their children later
            # Useful if we have list_child on it but no read_prop on the child record
            if "dnsZone" in entry["objectClass"]:
                dnsZones.append(entry["distinguishedName"])
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

            # Sometimes domain is in multiple dnsZones
            if domain_name in domain_set:
                continue
            yield_entry = {"recordName": domain_name}
            domain_set.add(domain_name)
            for record in entry["dnsRecord"]:
                try:
                    if record["Type"] not in yield_entry:
                        yield_entry[record["Type"]] = []
                    if record["Type"] in ["A", "AAAA", "NS", "CNAME", "PTR", "TXT"]:
                        yield_entry[record["Type"]].append(record["Data"])
                    elif record["Type"] == "MX":
                        yield_entry[record["Type"]].append(record["Data"]["Name"])
                    elif record["Type"] == "SRV":
                        yield_entry[record["Type"]].append(
                            f"{record['Data']['Target']}:{record['Data']['Port']}"
                        )
                    elif record["Type"] == "SOA":
                        yield_entry[record["Type"]].append({
                            "PrimaryServer": record["Data"]["PrimaryServer"],
                            "zoneAdminEmail": record["Data"]["zoneAdminEmail"].replace(
                                ".", "@", 1
                            ),
                        })
                except KeyError:
                    LOG.error("[-] KeyError for record: " + record)
                    continue
            yield yield_entry

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
        except (NoResultError, LDAPSearchException):
            continue
        for entry in entries:
            if entry.get("objectClass") or entry["distinguishedName"] == searchbase:
                continue

            domain_parts = entry["distinguishedName"].split(",")
            domain_suffix = domain_parts[1].split("=")[1]

            domain_name = domain_parts[0].split("=")[1]
            if no_detail and re.match("|".join(prefix_blacklist), domain_name):
                continue

            if (
                domain_name[-1] != "."
            ):  # Then it's probably not a fqdn, suffix certainly needed
                domain_name = f"{domain_name}.{domain_suffix}"

            ip_addr = domain_name.split(".in-addr.arpa")
            if len(ip_addr) > 1:
                decimals = ip_addr[0].split(".")
                decimals.reverse()
                while len(decimals) < 4:
                    decimals.append("0")
                domain_name = ".".join(decimals)
            # If domain has already been retrieved when searching with dnsNode filter (beacuse we had read_prop on it)
            # Or domain is in multiple dnsZones
            if domain_name in domain_set:
                continue
            domain_set.add(domain_name)
            yield {"recordName": domain_name}


def membership(conn, target: str, no_recurse: bool = False):
    """
    Retrieve SID and SAM Account Names of all groups a target belongs to

    :param target: sAMAccountName, DN, GUID or SID of the target
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


def trusts(conn, transitive_trust: bool = False, dns: str = ""):
    """
    Display trusts in an ascii tree starting from the DC domain as tree root. A->B means A can auth on B and A-<B means B can auth on A, A-<>B means bidirectionnal

    :param transitive_trust: Try to fetch transitive trusts (you should start from a dc of your user domain to have more complete results)
    :param dns: custom DNS IP (useful if current DC is not a GC and system DNS and DC DNS can't resolve trusts domains)
    """
    # Get all forest partitions of domain type
    # partitions = conn.ldap.bloodysearch("CN=Partitions," + conn.ldap.configNC, "(&(objecClass=crossRef)(systemFlags=3))", attr=["nCName"])

    # Get the host domain as root for the trust tree
    trust_root_domain = (".".join(conn.ldap.domainNC.split(",DC="))).split("DC=")[1]

    def fetchTrusts(conn, domain_name, trust_dict, dns):
        if domain_name:
            try:
                gc = utils.findReachableServer(conn, domain_name, "gc", dns)
            except resolver.NoAnswer:
                gc = None
            if not gc:
                LOG.warning(
                    f"[!] No Global Catalog found for {domain_name}, try to provide one"
                    " manually in --host"
                )
                return {}

        else:
            gc = conn.conf.host

        # Switch connection to a GC but on LDAP port to increase firewall bypass chances
        # Anyway we can access all partitions hosted by the DC on LDAP port too
        # We try to find a GC because we're sure it has all forest partitions but:
        # TODO: we could check by who has the NC replicas we need until we collect all the replicas
        conn.conf.scheme = "ldap"
        conn.conf.host = gc
        conn.rebind()

        # Tree root is the DC domain
        trust_to_explore = set()
        trusts = conn.ldap.bloodysearch(
            "",
            "(objectClass=trustedDomain)",
            attr=["trustDirection", "trustPartner", "trustAttributes", "trustType"],
            search_scope=Scope.SUBTREE,
            raw=True,
            controls=[utils.phantomRoot()],
        )
        for trust in trusts:
            already_in_tree = (
                ((trust["distinguishedName"]).rsplit("CN=System,", 1)[1]).replace(
                    "DC=", ""
                )
            ).replace(",", ".")
            if already_in_tree not in trust_dict:
                trust_dict[already_in_tree] = {}
            trust_dict[already_in_tree][trust["trustPartner"][0].decode()] = trust

            # We already have access to all the partitions of the forest through the GC we don't need to connect to other forest DCs
            if (
                common.TRUST_ATTRIBUTES["WITHIN_FOREST"]
                & int(trust["trustAttributes"][0].decode())
                > 0
            ):
                continue
            # We assume user belong to forest of provided DC in --host so we can explore external trusts only if we can auth on it (inbound)
            if (
                common.TRUST_DIRECTION["INBOUND"]
                & int(trust["trustDirection"][0].decode())
                > 0
            ):
                trust_to_explore.add(trust["trustPartner"][0].decode())

        return trust_to_explore

    forest_name = ""
    # Find a GC
    # Check if current DC is a GC
    NTDSDSA_OPT_IS_GC = 1
    nTDSDSA_options = next(
        conn.ldap.bloodysearch(conn.ldap._serverinfo["dsServiceName"], attr=["options"])
    )["options"]
    if nTDSDSA_options & NTDSDSA_OPT_IS_GC == 0:
        LOG.debug("[*] Current DC is not a GC, let's find one")
        forest_name = (
            ".".join(conn.ldap._serverinfo["rootDomainNamingContext"].split(",DC="))
        ).split("DC=")[1]

    trust_dict = {}
    trust_to_explore = fetchTrusts(conn, forest_name, trust_dict, dns)

    # We don't do it on foreign trust because there is no transitivity between 3 forests (A<->B<->C) A doesn't have trust on C even if B has it
    if transitive_trust:
        if not conn.conf.domain:
            LOG.warning(
                "[!] No domain (-d, --domain) provided, transitive trust will not be"
                " performed"
            )
        elif conn.conf.domain not in trust_dict:
            LOG.warning(
                "[!] User doesn't belong to this forest, transitive trusts will not be"
                " performed"
            )
        else:
            LOG.info(
                "[+] Forest trusts fetched, performing transitive trusts resolution"
            )
            for domain_name in trust_to_explore:
                fetchTrusts(conn, domain_name, trust_dict, dns)

    if not trust_dict:
        LOG.warning("[!] No Trusts found")
    else:
        tree = {}
        asciitree.branchFactory({":" + trust_root_domain: tree}, [], trust_dict)
        tree_printer = asciitree.LeftAligned()
        print(tree_printer({trust_root_domain: tree}))


def object(
    conn, target: str, attr: str = "*", resolve_sd: bool = False, raw: bool = False
):
    """
    Retrieve LDAP attributes for the target object provided, binary data will be outputted in base64

    :param target: sAMAccountName, DN, GUID or SID of the target (if you give an empty string "" prints rootDSE)
    :param attr: attributes to retrieve separated by a comma, retrieves all the attributes by default
    :param resolve_sd: if set, permissions linked to a security descriptor will be resolved (see bloodyAD github wiki/Access-Control for more information)
    :param raw: if set, will return attributes as sent by the server without any formatting, binary data will be outputted in base64
    """
    attributesSD = [
        "nTSecurityDescriptor",
        "msDS-GroupMSAMembership",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
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
):
    """
    Search in LDAP database, binary data will be outputed in base64

    :param base: DN of the parent object
    :param filter: filter to apply to the LDAP search (see Microsoft LDAP filter syntax)
    :param attr: attributes to retrieve separated by a comma
    :param resolve_sd: if set, permissions linked to a security descriptor will be resolved (see bloodyAD github wiki/Access-Control for more information)
    :param raw: if set, will return attributes as sent by the server without any formatting, binary data will be outputed in base64
    """
    attributesSD = [
        "nTSecurityDescriptor",
        "msDS-GroupMSAMembership",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]
    if base == "DOMAIN":
        base = conn.ldap.domainNC
    entries = conn.ldap.bloodysearch(
        base, filter, search_scope=Scope.SUBTREE, attr=attr.split(","), raw=raw
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
    # partition: Literal["DOMAIN", "DNS", "ALL"] = "DOMAIN"
):
    """
    Retrieve objects writable by client

    :param otype: type of writable object to retrieve
    :param right: type of right to search
    :param detail: if set, displays attributes/object types you can write/create for the object
    """
    # :param partition: directory partition a.k.a naming context to explore

    ldap_filter = ""
    if otype == "USER":
        ldap_filter = "(sAMAccountType=805306368)"
    else:
        if otype == "ALL":
            objectClass = "*"
        elif otype == "OU":
            objectClass = "container"
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
            searchbase, ldap_filter, search_scope=Scope.SUBTREE, attr=attr_params.keys()
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
