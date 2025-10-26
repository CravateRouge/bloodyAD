from bloodyAD import utils, asciitree
from bloodyAD.exceptions import LOG
from bloodyAD.network.ldap import Scope
from bloodyAD.exceptions import NoResultError
from badldap.commons.exceptions import LDAPSearchException
from typing import Literal
import re
import json
import base64


async def bloodhound(conn, transitive: bool = False, path: str = "CurrentPath"):
    """
    BloodHound CE collector (WARNING: This script is still in development. It only provides the basics - ADCS ESC and other complex nodes aren't supported yet)

    :param transitive: if set, will try to reach trusts to have more complete results (you should start from a dc of your user domain to have more complete results)
    :param path: filepath for the generated zip file
    """
    from badldap import bloodhound

    output_path = None
    if path != "CurrentPath":
        output_path = path
    ldap = await conn.getLdap()
    bh = bloodhound.MSLDAPDump2Bloodhound(ldap.co_url, follow_trusts=transitive, output_path=output_path)
    await bh.run()

async def children(conn, target: str = "DOMAIN", otype: str = "*", direct: bool = False):
    """
    List children for a given target object

    :param target: sAMAccountName, DN or SID of the target
    :param otype: special keyword "useronly" or objectClass of objects to fetch e.g. user, computer, group, trustedDomain, organizationalUnit, container, groupPolicyContainer, msDS-GroupManagedServiceAccount, etc
    :param direct: Fetch only direct children of target
    """
    ldap = await conn.getLdap()
    if target == "DOMAIN":
        target = ldap.domainNC
    scope = Scope.LEVEL if direct else Scope.SUBTREE
    if otype == "useronly":
        otype_filter = "sAMAccountType=805306368"
    else:
        otype_filter = f"objectClass={otype}"
    async for entry in ldap.bloodysearch(
        target,
        f"(&({otype_filter})(!(distinguishedName={target})))",
        search_scope=scope,
        attr=["distinguishedName"],
        controls=[("1.2.840.113556.1.4.417", True, None)]
    ):
        yield entry


async def dnsDump(conn, zone: str = None, no_detail: bool = False, transitive: bool = False):
    """
    Retrieve DNS records of the Active Directory readable/listable by the user

    :param zone: if set, prints only records in this zone
    :param no_detail: if set doesn't include system records such as _ldap, _kerberos, @, etc
    :param transitive: if set, try to fetch dns records in AD trusts (you should start from a DC of your user domain to have exhaustive results)
    """

    async def domainDnsDump(conn, zone=None, no_detail=False):
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

        ldap = await conn.getLdap()
        dnsZones = []
        for nc in ldap.appNCs + [ldap.domainNC]:
            try:
                entries = ldap.bloodysearch(
                    nc,
                    filter,
                    search_scope=Scope.SUBTREE,
                    attr=["dnsRecord", "name", "objectClass"],
                )
                async for entry in entries:
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
                            LOG.error("KeyError for record: " + record)
                            continue

                    yield yield_entry
            except (NoResultError, LDAPSearchException) as e:
                if type(e) is NoResultError:
                    LOG.warning(f"No readable record found in {nc}")
                else:
                    LOG.warning(f"{nc} couldn't be read on {conn.conf.host}")
                continue
        # List record names if we have list child right on dnsZone or MicrosoftDNS container but no READ_PROP on record object
        for nc in ldap.appNCs:
            dnsZones.append(f"CN=MicrosoftDNS,{nc}")
        dnsZones.append(f"CN=MicrosoftDNS,CN=System,{ldap.domainNC}")
        for searchbase in dnsZones:
            try:
                entries = ldap.bloodysearch(
                    searchbase,
                    "(objectClass=*)",
                    search_scope=Scope.SUBTREE,
                    attr=["objectClass"],
                )
                async for entry in entries:
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
                    LOG.warning(f"No listable record found in {nc}")
                else:
                    LOG.warning(f"{nc} couldn't be read on {conn.conf.host}")
                continue

    # Used to avoid duplicate entries if there is the same record in multiple partitions
    record_dict = {}
    record_entries = []
    ldap = await conn.getLdap()
    if transitive:
        trustmap = await ldap.getTrustMap()
        for trust in trustmap.values():
            if "conn" in trust:
                record_entries.append(domainDnsDump(trust["conn"], zone, no_detail))
    else:
        record_entries.append(domainDnsDump(conn, zone, no_detail))

    basic_records = []
    for records in record_entries:
        async for r in records:
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


async def membership(conn, target: str, no_recurse: bool = False):
    """
    Retrieve SID and SAM Account Names of all groups a target belongs to

    :param target: sAMAccountName, DN or SID of the target
    :param no_recurse: if set, doesn't retrieve groups where target isn't a direct member
    """
    ldap = await conn.getLdap()
    ldap_filter = ""
    if no_recurse:
        entries = ldap.bloodysearch(target, attr=["objectSid", "memberOf"])
        async for entry in entries:
            for group in entry.get("memberOf", []):
                ldap_filter += f"(distinguishedName={group})"
        if not ldap_filter:
            LOG.warning("No direct group membership found")
            return
    else:
        # [MS-ADTS] 3.1.1.4.5.19 tokenGroups, tokenGroupsNoGCAcceptable
        attr = "tokenGroups"
        entries = ldap.bloodysearch(target, attr=[attr])
        async for entry in entries:
            try:
                for groupSID in entry[attr]:
                    ldap_filter += f"(objectSID={groupSID})"
            except KeyError:
                LOG.warning("No membership found")
                return
        if not ldap_filter:
            LOG.warning("no GC Server available, the set of groups might be incomplete")
            attr = "tokenGroupsNoGCAcceptable"
            entries = ldap.bloodysearch(target, attr=[attr])
            async for entry in entries:
                for groupSID in entry[attr]:
                    ldap_filter += f"(objectSID={groupSID})"

    entries = ldap.bloodysearch(
        ldap.domainNC,
        f"(|{ldap_filter})",
        search_scope=Scope.SUBTREE,
        attr=["objectSID", "sAMAccountName"],
    )
    async for entry in entries:
        yield entry


async def trusts(conn, transitive: bool = False):
    """
    Display trusts in an ascii tree starting from the DC domain as tree root. A->B means A can auth on B and A-<B means B can auth on A, A-<>B means bidirectional

    :param transitive: Try to fetch transitive trusts (you should start from a dc of your user domain to have more complete results)
    """
    ldap = await conn.getLdap()
    trust_dict = await ldap.getTrusts(transitive, conn.conf.dns)

    # Get the host domain as root for the trust tree
    trust_root_domain = ldap.domainname
    if trust_dict:
        tree = {}
        asciitree.branchFactory({":" + trust_root_domain: tree}, [], trust_dict)
        tree_printer = asciitree.LeftAligned()
        print(tree_printer({trust_root_domain: tree}))


async def object(
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
    ldap = await conn.getLdap()
    entries = ldap.bloodysearch(target, attr=attr.split(","), raw=raw)
    rendered_entries = utils.renderSearchResult(entries)
    if resolve_sd and not raw:
        async for entry in rendered_entries:
            for attrSD in attributesSD:
                if attrSD in entry:
                    e = entry[attrSD]
                    if not isinstance(e, list):
                        entry[attrSD] = await utils.renderSD(e, conn)
                    else:
                        entry[attrSD] = [await utils.renderSD(sd, conn) for sd in e]
            yield entry
    else:
        async for entry in rendered_entries:
            yield entry


async def search(
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
    ldap = await conn.getLdap()
    if base == "DOMAIN":
        base = ldap.domainNC
    # RFC2251 4.1.12 Controls
    # control ::= (controlType, criticality, controlValue)
    controls = [(oid,True,None) for oid in c]
    entries = ldap.bloodysearch(
        base, filter, search_scope=Scope.SUBTREE, attr=attr.split(","), raw=raw, controls=controls
    )
    rendered_entries = utils.renderSearchResult(entries)
    if resolve_sd and not raw:
        async for entry in rendered_entries:
            for attrSD in attributesSD:
                if attrSD in entry:
                    e = entry[attrSD]
                    if not isinstance(e, list):
                        entry[attrSD] = await utils.renderSD(e, conn)
                    else:
                        entry[attrSD] = [await utils.renderSD(sd, conn) for sd in e]
            yield entry
    else:
        async for entry in rendered_entries:
            yield entry


def _create_ldapentry_from_entry(entry, ldap):
    """
    Create a badldap ldapentry object from a dictionary entry based on objectClass.
    Returns a tuple of (ldapentry, needs_domainsid) where needs_domainsid indicates
    if the to_bh method needs domainsid parameter.
    """
    from badldap.ldap_objects import (
        MSADUser, MSADMachine, MSADGroup, MSADOU, MSADGPO, 
        MSADContainer, MSADDMSAUser, MSADGMSAUser
    )
    
    object_classes = entry.get('objectClass', [])
    sam_account_type = entry.get('sAMAccountType', 0)
    
    # Determine the appropriate class based on objectClass and sAMAccountType
    needs_domainsid = False
    if 'msDS-GroupManagedServiceAccount' in object_classes:
        ldapentry = MSADGMSAUser.from_ldap(entry)
    elif 'msDS-ManagedServiceAccount' in object_classes:
        ldapentry = MSADDMSAUser.from_ldap(entry)
    elif sam_account_type == 805306368 or 'user' in object_classes:
        ldapentry = MSADUser.from_ldap(entry)
    elif sam_account_type == 805306369 or 'computer' in object_classes:
        ldapentry = MSADMachine.from_ldap(entry)
    elif 'group' in object_classes:
        ldapentry = MSADGroup.from_ldap(entry)
    elif 'groupPolicyContainer' in object_classes:
        ldapentry = MSADGPO.from_ldap(entry)
        needs_domainsid = True
    elif 'organizationalUnit' in object_classes:
        ldapentry = MSADOU.from_ldap(entry)
        needs_domainsid = True
    elif 'container' in object_classes:
        ldapentry = MSADContainer.from_ldap(entry)
        needs_domainsid = True
    else:
        # Default to container for unknown types
        ldapentry = MSADContainer.from_ldap(entry)
        needs_domainsid = True
    
    return ldapentry, needs_domainsid


def _parse_ntsecurity_descriptor(entry, ldapentry, schema):
    """
    Parse the nTSecurityDescriptor attribute and create ACEs using parse_binary_acl.
    Returns a tuple of (meta, relations) where meta contains IsACLProtected and relations is a list of ACE dicts.
    """
    from badldap.external.bloodhoundpy.acls import parse_binary_acl
    
    nt_security_descriptor = entry.get('nTSecurityDescriptor')
    if not nt_security_descriptor:
        return {'IsACLProtected': False}, []
    
    # Determine entry type for parse_binary_acl
    object_classes = entry.get('objectClass', [])
    sam_account_type = entry.get('sAMAccountType', 0)
    
    if 'msDS-GroupManagedServiceAccount' in object_classes or 'msDS-ManagedServiceAccount' in object_classes:
        entrytype = 'user'
    elif sam_account_type == 805306368 or 'user' in object_classes:
        entrytype = 'user'
    elif sam_account_type == 805306369 or 'computer' in object_classes:
        entrytype = 'computer'
    elif 'group' in object_classes:
        entrytype = 'group'
    elif 'groupPolicyContainer' in object_classes:
        entrytype = 'gpo'
    elif 'organizationalUnit' in object_classes:
        entrytype = 'ou'
    elif 'container' in object_classes:
        entrytype = 'container'
    elif 'domain' in object_classes or 'domainDNS' in object_classes:
        entrytype = 'domain'
    else:
        entrytype = 'base'
    
    # Prepare bh_entry with necessary fields for parse_binary_acl
    dn = entry.get('distinguishedName', '')
    bh_entry = {
        'Properties': {
            'haslaps': False  # Default to False, can be enhanced later if needed
        }
    }
    
    # For computers, check if LAPS is enabled
    if entrytype == 'computer':
        # Check if ms-Mcs-AdmPwd or ms-LAPS-EncryptedPassword attribute exists
        if entry.get('ms-Mcs-AdmPwd') or entry.get('ms-LAPS-EncryptedPassword'):
            bh_entry['Properties']['haslaps'] = True
    
    # Parse the ACL
    dn_result, bh_entry, relations = parse_binary_acl(
        dn.upper(), 
        bh_entry, 
        entrytype, 
        nt_security_descriptor, 
        schema
    )
    
    meta = {'IsACLProtected': bh_entry.get('IsACLProtected', False)}
    return meta, relations


def _check_upn_writable(entry):
    """
    Check if userPrincipalName is in the allowedAttributesEffective list.
    Returns True if userPrincipalName is writable.
    """
    allowed_attrs = entry.get('allowedAttributesEffective', [])
    return 'userPrincipalName' in allowed_attrs


# TODO: Search writable for application partitions too?
async def writable(
    conn,
    otype: Literal["ALL", "OU", "USER", "COMPUTER", "GROUP", "DOMAIN", "GPO"] = "ALL",
    right: Literal["ALL", "WRITE", "CHILD"] = "ALL",
    detail: bool = False,
    exclude_del: bool = False,
    bh: str = None
    # partition: Literal["DOMAIN", "DNS", "ALL"] = "DOMAIN"
):
    """
    Retrieve objects writable by client

    :param otype: type of writable object to retrieve
    :param right: type of right to search
    :param detail: if set, displays attributes/object types you can write/create for the object
    :param exclude_del: if set, exclude deleted objects
    :param bh: if set, creates a BloodHound-compatible JSON file at the specified path
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
    

    # Build attributes list - include objectSid and objectGUID if with_sid is True
    requested_attributes = list(attr_params.keys())
    controls = None
    if not exclude_del:
        requested_attributes.append("objectSid")
        controls = [("1.2.840.113556.1.4.417", True, None)]

    ldap = await conn.getLdap()
    searchbases = []
    # if partition == "DOMAIN":
    searchbases.append(ldap.domainNC)
    # elif partition == "DNS":
    #     searchbases.append(ldap.applicationNCs) # A definir https://learn.microsoft.com/en-us/windows/win32/ad/enumerating-application-directory-partitions-in-a-forest
    # else:
    #     searchbases.append(ldap.NCs) # A definir
    
    # If --bh is specified, we need to collect entries and create BloodHound JSON
    if bh:
        await _writable_bh(conn, ldap, searchbases, ldap_filter, attr_params, requested_attributes, controls, bh)
        return
    
    # Regular output mode
    right_entry = {}
    for searchbase in searchbases:
        async for entry in ldap.bloodysearch(
            searchbase, ldap_filter, search_scope=Scope.SUBTREE, attr=requested_attributes, controls=controls
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
                # Build base result with distinguishedName
                result = {"distinguishedName": entry["distinguishedName"]}

                if "objectSid" in entry:
                    result["objectSid"] = entry["objectSid"]
                
                # Merge right_entry into result
                result.update(right_entry)
                
                yield result
                right_entry = {}


async def _writable_bh(conn, ldap, searchbases, ldap_filter, attr_params, requested_attributes, controls, output_path):
    """
    Generate BloodHound-compatible JSON for writable objects.
    """
    from badldap.external.bloodhoundpy.resolver import resolve_aces
    
    # Get domain info for BloodHound
    domainname = ldap.domainname
    adinfo = await ldap.get_ad_info()
    domainsid = str(adinfo.objectSid)
    
    # Fetch schema for parse_binary_acl
    schema = {}
    # Fetch required schema entries
    schema_entries = [
        'ms-Mcs-AdmPwd',
        'ms-LAPS-EncryptedPassword',
        'ms-DS-Key-Credential-Link',
        'Service-Principal-Name',
        'User-Principal-Name',
    ]
    
    for entry_name in schema_entries:
        try:
            entry = await ldap.get_schemaentry_by_name(entry_name)
            if entry:
                schema[entry.name.lower()] = str(entry.schemaIDGUID)
        except Exception as e:
            LOG.debug(f'Error fetching schema entry {entry_name}: {e}')
    
    # Build a simple object cache (SID -> object info)
    ocache = {}
    
    # Collect writable entries
    writable_entries = []
    for searchbase in searchbases:
        async for entry in ldap.bloodysearch(
            searchbase, ldap_filter, search_scope=Scope.SUBTREE, attr=requested_attributes, controls=controls
        ):
            # Check if any of the writable attributes are non-null
            has_writable = False
            for attr_name in attr_params.keys():
                if attr_name in entry and entry[attr_name]:
                    has_writable = True
                    break
            
            if has_writable:
                writable_entries.append(entry)
    
    # Build lookup cache for resolve_aces
    # Query all objects to build the cache
    LOG.info(f"Building object cache for ACE resolution...")
    all_attrs = ['distinguishedName', 'objectSid', 'objectGUID', 'sAMAccountName', 'sAMAccountType', 'objectClass']
    async for entry in ldap.bloodysearch(searchbases[0], '(objectClass=*)', search_scope=Scope.SUBTREE, attr=all_attrs):
        object_sid = entry.get('objectSid')
        if object_sid:
            sam_account_type = entry.get('sAMAccountType', 0)
            object_classes = entry.get('objectClass', [])
            
            # Determine object type
            if sam_account_type == 805306368 or 'user' in object_classes:
                otype = 'User'
            elif sam_account_type == 805306369 or 'computer' in object_classes:
                otype = 'Computer'
            elif 'group' in object_classes:
                otype = 'Group'
            elif 'groupPolicyContainer' in object_classes:
                otype = 'GPO'
            elif 'organizationalUnit' in object_classes:
                otype = 'OU'
            elif 'container' in object_classes:
                otype = 'Container'
            elif 'domain' in object_classes or 'domainDNS' in object_classes:
                otype = 'Domain'
            else:
                otype = 'Base'
            
            ocache[str(object_sid)] = {
                'ObjectIdentifier': str(object_sid),
                'ObjectType': otype
            }
    
    # Process each writable entry and create BloodHound JSON
    LOG.info(f"Processing {len(writable_entries)} writable entries...")
    
    # Get the current user's SID once (for WriteUPN edges)
    current_user_sid = None
    try:
        current_user_info = await ldap.get_user()
        if current_user_info and current_user_info.objectSid:
            current_user_sid = str(current_user_info.objectSid)
    except Exception as e:
        LOG.debug(f"Could not get current user info: {e}")
    
    bh_data = {
        "data": [],
        "meta": {
            "count": 0,
            "type": "writable",
            "version": 5
        }
    }
    
    for entry in writable_entries:
        # Query all attributes for this entry, including nTSecurityDescriptor and allowedAttributesEffective
        dn = entry.get('distinguishedName')
        full_entry_results = ldap.bloodysearch(
            dn, '(objectClass=*)', search_scope=Scope.BASE, 
            attr=['*', 'nTSecurityDescriptor', 'allowedAttributesEffective']
        )
        
        full_entry = None
        async for fe in full_entry_results:
            full_entry = fe
            break
        
        if not full_entry:
            continue
        
        # Create ldapentry object
        ldapentry, needs_domainsid = _create_ldapentry_from_entry(full_entry, ldap)
        
        # Convert to BloodHound format
        if needs_domainsid:
            bh_entry = ldapentry.to_bh(domainname, domainsid)
        else:
            bh_entry = ldapentry.to_bh(domainname)
        
        # Parse ACL
        meta, relations = _parse_ntsecurity_descriptor(full_entry, ldapentry, schema)
        bh_entry['IsACLProtected'] = meta['IsACLProtected']
        
        # Resolve ACEs
        bh_entry['Aces'] = resolve_aces(relations, domainname, domainsid, ocache)
        
        # Add WriteUPN edge if userPrincipalName is writable
        if current_user_sid and _check_upn_writable(full_entry):
            # Add WriteUPN edge for the authenticated user
            bh_entry['Aces'].append({
                'PrincipalSID': current_user_sid,
                'PrincipalType': 'User',
                'RightName': 'WriteUPN',
                'IsInherited': False
            })
        
        bh_data['data'].append(bh_entry)
        bh_data['meta']['count'] += 1
    
    # Write to file
    with open(output_path, 'w') as f:
        json.dump(bh_data, f, indent=2)
    
    LOG.info(f"BloodHound JSON written to {output_path} with {bh_data['meta']['count']} entries")
