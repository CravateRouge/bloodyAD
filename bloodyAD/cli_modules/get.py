from bloodyAD import utils, asciitree, ConnectionHandler
from bloodyAD.exceptions import LOG
from bloodyAD.network.ldap import Scope
from bloodyAD.exceptions import NoResultError
from bloodyAD.formatters import common
from msldap.commons.exceptions import LDAPSearchException
from typing import Literal
import re, asyncio, collections


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
        except (NoResultError, LDAPSearchException):
            continue

        domain_set = set()
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

            # Sometimes domain is in multiple dnsZones
            if domain_name in domain_set:
                continue
            yield_entry = {"recordName": domain_name}
            domain_set.add(domain_name)
            for record in entry.get("dnsRecord", []):
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
                        yield_entry[record["Type"]].append(
                            {
                                "PrimaryServer": record["Data"]["PrimaryServer"],
                                "zoneAdminEmail": record["Data"][
                                    "zoneAdminEmail"
                                ].replace(".", "@", 1),
                            }
                        )
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
            # If we can get objectClass it means we have a READ_PROP on the record object so we already found it before
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
    Display trusts in an ascii tree starting from the DC domain as tree root. A->B means A can auth on B and A-<B means B can auth on A, A-<>B means bidirectional

    :param transitive_trust: Try to fetch transitive trusts (you should start from a dc of your user domain to have more complete results)
    :param dns: custom DNS IP (useful if current DC is not a GC and system DNS and DC DNS can't resolve trusts domains)
    """

    async def asyncTrusts(conn, transitive_trust: bool = False, dns: str = ""):
        # Get the host domain as root for the trust tree
        trust_root_domain = (".".join(conn.ldap.domainNC.split(",DC="))).split("DC=")[1]

        # forest_name = ""
        # forest_name = (
        #     ".".join(conn.ldap._serverinfo["rootDomainNamingContext"].split(",DC="))
        # ).split("DC=")[1]

        # We shouldn't need to make trust_dict async_safe cause there is no call to trust_dict before an await access it in fetchTrusts()
        trust_dict = {}
        trust_to_explore = await fetchTrusts(conn, trust_dict, dns)

        # We don't do it on foreign trust because there is no transitivity between 3 forests (A<->B<->C) A doesn't have trust on C even if B has it
        if transitive_trust:
            if not conn.conf.domain:
                LOG.warning(
                    "[!] No domain (-d, --domain) provided, transitive trust search will not be"
                    " performed"
                )
            elif conn.conf.domain not in trust_dict:
                LOG.warning(
                    "[!] User doesn't belong to this forest, transitive trust search will not be"
                    " performed"
                )
            else:
                LOG.info(
                    "[+] Forest trusts fetched, performing transitive trust search"
                )
                tasks = []
                for domain_name, parent_conn in trust_to_explore.items():
                    tasks.append(fetchTrusts(parent_conn, trust_dict, dns, domain_name))
                await asyncio.gather(*tasks)

        if not trust_dict:
            LOG.warning("[!] No Trusts found")
        else:
            tree = {}
            asciitree.branchFactory({":" + trust_root_domain: tree}, [], trust_dict)
            tree_printer = asciitree.LeftAligned()
            print(tree_printer({trust_root_domain: tree}))

    async def fetchTrusts(conn, trust_dict, dns, domain_name=""):
        # Search request to look into all available domain partitions on the dc for trusts relationships
        # We don't care if because of simultaneous dc search there are duplicates, the overhead is minor, trusts are not many
        search_params = {
            "base": "",
            "ldap_filter": "(objectClass=trustedDomain)",
            "attr": ["trustDirection", "trustPartner", "trustAttributes", "trustType"],
            "search_scope": Scope.SUBTREE,
            "raw": True,
            "controls": [utils.phantomRoot()],
        }
        trusts = await searchInForest(conn, search_params, dns, domain_name)
        # Tree root is the DC domain
        trust_to_explore = {}
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
            # We assume user belongs to forest of provided DC in --host so we can explore external trusts only if we can auth on them (inbound)
            if (
                common.TRUST_DIRECTION["INBOUND"]
                & int(trust["trustDirection"][0].decode())
                > 0
            ):
                # NOTE: If we need later we can add more than one parent_conn as a failsafe and then try to co to trust with more than one parent_conn
                # Useful when using kerberos and performing cross realm
                trust_to_explore[trust["trustPartner"][0].decode()] = trust[
                    "parent_conn"
                ]
        return trust_to_explore

    async def searchInForest(conn, search_params, dns, domain_name="", allow_gc=True):
        # If domain_name is provided it means we try to reach a domain outside of current "conn" forest so we have to find a server that we can reach for this outsider domain and then we search the entire forest related to this outsider domain
        newconn = conn
        if domain_name:
            host_params = await utils.findReachableDomainServer(
                domain_name,
                newconn.ldap.current_site,
                dns_addr=dns,
                dc_dns=newconn.conf.dcip,
            )
            if not host_params:
                LOG.warning(
                    f"[!] No reachable server found for {domain_name}, try to provide one"
                    " manually in --host"
                )
                return {}
            schemes = {389: "ldap", 636: "ldaps", 3268: "gc", 3269: "gc-ssl"}
            newconn = conn.copy(
                scheme=schemes[host_params["port"]],
                host=host_params["name"],
                dcip=host_params["ip"],
            )

        search_results = []
        # dc is a gc for this forest, hosting every records we want, we don't need to look for other domain partitions on other dc
        # Except if we're looking for attributes no replicated in GC, then searchInForest must be called with allow_gc=False
        if newconn.ldap.is_gc and allow_gc:
            search_results = await searchInPartition(newconn, search_params, dns)
            if newconn != conn and newconn._ldap:
                newconn.ldap.close()
            return search_results

        # Find all domain partitions in the forest and dc hosting them
        try:
            # Get all domain partitions in the forest
            # partitions = conn.ldap.bloodysearch("CN=Partitions," + conn.ldap.configNC, "(&(objectClass=crossRef)(systemFlags=3))", attr=["nCName"])
            # Find nTDSDSA objects containing msDS-HasDomainNCs and server objects parents containing dNSHostname
            entries = newconn.ldap.bloodysearch(
                "CN=Sites," + newconn.ldap.configNC,
                "(|(objectClass=nTDSDSA)(objectClass=server))",
                search_scope=Scope.SUBTREE,
                attr=["msDS-HasDomainNCs", "dNSHostName"],
            )
            # Put domain partitions and hostnames together by matching server distinguished name on them
            forest_servers = collections.defaultdict(dict)
            for entry in entries:
                hostname = entry.get("dNSHostName")
                if hostname:
                    forest_servers[entry["distinguishedName"]]["host"] = hostname
                elif "msDS-HasDomainNCs" in entry:
                    parent_name = (entry["distinguishedName"]).split(",", 1)[1]
                    forest_servers[parent_name]["partitions"] = entry[
                        "msDS-HasDomainNCs"
                    ]
                else:
                    LOG.warning(
                        f"[!] No dNSHostName found for DC {entry['distinguishedName']}, the DC may have been demoted or have synchronization issues"
                    )
            # Reorganize dict on domain so domain becomes the key containing the hosts
            forest_partitions = collections.defaultdict(list)
            for dn, attributes in forest_servers.items():
                if "host" not in attributes:
                    LOG.warning(
                        f"[!] No dNSHostName found for DC {dn}, the DC may have been demoted or have synchronization issues"
                    )
                for p in attributes.get("partitions"):
                    forest_partitions[p].append(
                        {"type": ["A", "AAAA"], "name": attributes["host"]}
                    )
            tasks = []
            for p, hosts in forest_partitions.items():
                tasks.append(searchInPartition(newconn, search_params, dns, p, hosts))
            search_results = await asyncio.gather(*tasks)
            search_results = [entry for entries in search_results for entry in entries]
        except Exception as e:
            LOG.error(
                f"[!] Something went wrong when trying to perform searchInForest for {domain_name}"
            )
            LOG.error(f"[!] Error {type(e).__name__}: {e}")
        finally:
            if newconn != conn and newconn._ldap:
                newconn.ldap.close()
            return search_results

    async def searchInPartition(
        conn, bloodysearch_params, dns, partition="", host_records=[]
    ):
        schemes = {389: "ldap", 636: "ldaps", 3268: "gc", 3269: "gc-ssl"}
        # If host_records empty means the dc in "conn" is already the one we want to query
        if host_records:
            host_params = await utils.findReachableServer(
                host_records, dns, conn.conf.dcip
            )
            if not host_params:
                LOG.warning(
                    f"[!] No reachable server found for {partition}, try to provide one"
                    " manually in --host"
                )
                return {}
            newconn = conn.copy(
                scheme=schemes[host_params["port"]],
                host=host_params["name"],
                dcip=host_params["ip"],
            )

        else:
            newconn = conn

        search_result = []
        try:
            if bloodysearch_params["base"] == "domainNC":
                # The directory can be handled by others instances of the function so we have to duplicate it before modifying it
                bloodysearch_params = dict(bloodysearch_params)
                bloodysearch_params["base"] = newconn.ldap.domainNC
            # We add parent_conn to know which conn as the trust, useful for krb cross realm
            search_result = [
                {"parent_conn": newconn, **entry}
                for entry in newconn.ldap.bloodysearch(**bloodysearch_params)
            ]
        except Exception as e:
            LOG.error(
                f"[!] Something went wrong when trying to perform this ldap search: {bloodysearch_params} on {newconn.conf.host} with the {newconn.conf.scheme} protocol"
            )
            LOG.error(f"[!] Error {type(e).__name__}: {e}")
        finally:
            if newconn != conn and newconn._ldap:
                newconn.ldap.close()
            return search_result

    asyncio.get_event_loop().run_until_complete(
        asyncTrusts(conn, transitive_trust, dns)
    )


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
    Search in LDAP database, binary data will be outputted in base64

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
