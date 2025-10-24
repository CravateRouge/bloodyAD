from bloodyAD.formatters import accesscontrol, common, formatters
from bloodyAD.exceptions import NoResultError, TooManyResultsError, LOG
import re, os, enum, asyncio, urllib, collections
from functools import cached_property, lru_cache
from asn1crypto import core
from badldap.client import MSLDAPClient
from badldap.commons.factory import LDAPConnectionFactory
from badldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue
from badldap.network import reacher
from winacl import dtyp


class Scope(enum.Enum):
    BASE = 0
    LEVEL = 1
    SUBTREE = 2


class Change(enum.Enum):
    ADD = "add"
    DELETE = "delete"
    REPLACE = "replace"
    INCREMENT = "increment"


class NCType(enum.IntFlag):
    PARTIAL_DOM = 1
    FULL_DOM = 2
    APP = 4
    ALL = PARTIAL_DOM | FULL_DOM | APP


@lru_cache
def phantomRoot():
    # [MS-ADTS] 3.1.1.3.4.1.12
    # Search control to search in all NC replicas except applications replicas (DNS partitions)
    class SearchOptionsRequest(core.Sequence):
        _fields = [
            ("Flags", core.Integer),
        ]

    SERVER_SEARCH_FLAG_PHANTOM_ROOT = 2
    scontrols = SearchOptionsRequest({"Flags": SERVER_SEARCH_FLAG_PHANTOM_ROOT})
    LDAP_SERVER_SEARCH_OPTIONS_OID = "1.2.840.113556.1.4.1340"

    return (LDAP_SERVER_SEARCH_OPTIONS_OID, False, scontrols.dump())


class Ldap(MSLDAPClient):
    conf = None
    domainNC = None
    configNC = None
    # Format: {<AD domain name>:{"conn":<ConnectionHandler obj>, "domsid":<domain sid>}}
    # "conn" is optional
    conn = None
    co_url = None
    is_prettified = False

    def __init__(self, conn, target, credential):
        self._trustmap = collections.defaultdict(dict)
        self.conn = conn
        self.conf = conn.conf
        self.co_url = None
        super().__init__(target, credential, keepalive=True)
        self.isactive = False

    @classmethod
    async def create(cls, conn):
        """Async factory method to create and initialize an Ldap instance"""
        cnf = conn.conf

        # Because badldap uses a url format we have to encode everything properly
        encoded_cnf = {}
        for attr_name, attr_value in vars(cnf).items():
            if type(attr_value) is str:
                encoded_cnf[attr_name] = urllib.parse.quote(attr_value, safe="")
            else:
                encoded_cnf[attr_name] = attr_value

        auth = ""
        creds = ""
        username = ""
        key = ""
        params = "serverip=" + cnf.dcip

        if cnf.kerberos:
            username = "%s\\%s" % (encoded_cnf["domain"], encoded_cnf["username"])
            if cnf.dcip == cnf.host:
                raise ValueError(
                    "You can provide the IP in --dc-ip but you need to provide the"
                    " hostname in --host in order for kerberos to work"
                )
            params += "&dc=" + cnf.kdc
            if cnf.kdcc and cnf.realmc:
                params += f"&dcc={cnf.kdcc}&realmc={cnf.realmc}"
            auth = "kerberos-"
            key = encoded_cnf["key"]
            if cnf.crt:
                file_extension = cnf.crt.rsplit('.',1)[1]
                if file_extension in ["pfx", "p12"]:
                    auth += "pfx"
                elif file_extension == "pem":
                    auth += "pem"
                else:
                    LOG.warning("No .pem/.pfx extension detected, will try .pem")
                    auth += "pem"
                params += "&certdata=" + encoded_cnf["crt"]
                if cnf.key:
                    params += "&keydata=" + key
                    key = ""
                if cnf.password:
                    key = encoded_cnf["password"]
            elif key:
                auth += cnf.krbformat
                if cnf.format in ["b64", "hex"]:
                    auth += cnf.format
            else:
                if cnf.password:
                    if cnf.format in ["aes", "rc4"]:
                        auth += cnf.format
                    else:
                        auth += "password"
                    key = encoded_cnf["password"]
                else:
                    if os.name == "nt":
                        if cnf.certificate:
                            auth += "certstore"
                        else:
                            auth = "sspi-kerberos"
                    else:
                        raise ValueError(
                            "You should provide a -p 'password' or a kerberos ticket"
                            " via '-k <keyfile_type>=./myticket'"
                        )                   
        elif cnf.certificate:
            if cnf.crt:
                auth = "ssl"
                params += "&sslcert=" + encoded_cnf["crt"]
                if cnf.key:
                    params += "&sslkey=" + encoded_cnf["key"]
                if cnf.password:
                    params += "&sslpassword=" + encoded_cnf["password"]
            else:
                if os.name == "nt":
                    auth = "kerberos-certstore"
                else:
                    raise ValueError(
                        "Certstore only available on Windows, --certstore can't be left empty here"
                    )
        else:
            username = "%s\\%s" % (encoded_cnf["domain"], encoded_cnf["username"])
            if cnf.nthash:
                auth = "ntlm-nt"
                key = encoded_cnf["nthash"]
            else:
                key = encoded_cnf["password"]
                if not key:
                    if os.name == "nt":
                        auth = "sspi-ntlm"
                    else:
                        raise ValueError("You should provide a -p 'password'")
                else:
                    auth = "ntlm-pw"
                    if cnf.format in ["b64", "hex"]:
                        auth += cnf.format

        if cnf.timeout:
            params += f"&timeout={cnf.timeout}"
        if cnf.dns:
            params += "&dns=" + cnf.dns

        # If auth has been defined in config we replace auth we built with it
        if cnf.auth:
            auth = cnf.auth + '-' + auth.split("-",1)[1]
        auth = "+" + auth if auth else ""
        creds = username if username else ""
        creds = creds + ":" + key if key else creds
        creds = creds + "@" if creds else ""
        params = "/?" + params
        co_url = f"{cnf.scheme}{auth}://{creds}{encoded_cnf['host']}{params}"
        LOG.debug(f"Connection URL: {co_url}")
        ldap_factory = LDAPConnectionFactory.from_url(co_url)
        
        # Create instance
        instance = cls(conn, ldap_factory.target, ldap_factory.credential)
        instance.co_url = co_url
        
        # Connect asynchronously
        try:
            LOG.debug(f"Trying to connect to {cnf.host}...")
            _, err = await instance.connect()
            if err:
                raise err
            LOG.debug("Connection successful")
            instance.isactive = True
            instance.domainNC = instance._serverinfo["defaultNamingContext"]
            instance.configNC = instance._serverinfo["configurationNamingContext"]
            instance.schemaNC = instance._serverinfo["schemaNamingContext"]
            instance.appNCs = []
            for nc in instance._serverinfo["namingContexts"]:
                if nc in [instance.domainNC, instance.configNC, instance.schemaNC]:
                    continue
                instance.appNCs.append(nc)
        except Exception as e:
            raise e
        
        return instance

    async def bloodyadd(self, target, controls=None, **kwargs):
        if controls is not None:
            t = []
            for control in controls:
                t.append(
                    {
                        "controlType": control[0].encode(),
                        "criticality": control[1],
                        "controlValue": control[2],
                    }
                )
            controls = t
        _, err = await self.add(await self.dnResolver(target), controls=controls, **kwargs)
        if err:
            raise err

    async def close(self):
        if not self.isactive:
            return
        self.isactive = False
        for trust in self._trustmap.values():
            if "conn" in trust and trust["conn"] != self.conn:
                await trust["conn"].closeLdap()
        await self.disconnect()

    async def bloodydelete(self, target, *args):
        _, err = await self.delete(await self.dnResolver(target), *args)
        if err:
            raise err

    async def dnResolver(self, identity):
        """
        Return the DN for the object based on the parameters identity
        Args:
            identity: sAMAccountName, DN, UPN, GPO name or SID of the object
        """
        if ",dc=" in identity.lower():
            # identity is a DN, return as is
            # We do not try to validate it because it could be from another trusted domain
            return identity

        if identity.lower().startswith("s-1-"):
            # We assume identity is an SID
            ldap_filter = f"(objectSid={identity})"
        # For GPO name as GPO has no sAMAccountName
        elif identity.startswith("{"):
            ldap_filter = f"(name={identity})"
        elif "@" in identity:
            # Assume identity is a UPN
            ldap_filter = f"(userPrincipalName={identity})"
        else:
            # By default, we assume identity is a sam account name
            ldap_filter = f"(sAMAccountName={identity})"

        dn = ""
        entries = self.pagedsearch(
            ldap_filter, ["distinguishedName"], tree=self.domainNC
        )
        async for entry, err in entries:
            if err:
                raise err
            if dn:
                raise TooManyResultsError(self.domainNC, ldap_filter, entries)
            dn = entry["attributes"]["distinguishedName"]

        if not dn:
            # Try ambiguous name resolution as last resort for debug
            entries = self.pagedsearch(
            f"(anr={identity})", ["distinguishedName"], tree=self.domainNC
            )
            anr_dn = []
            async for entry, err in entries:
                if err:
                    raise err
                anr_dn.append(entry["attributes"]["distinguishedName"])
            if anr_dn:
                LOG.error(
                    f"No results found for '{identity}' but found entries that could match: {anr_dn}"
                )
            raise NoResultError(self.domainNC, ldap_filter)

        return dn

    async def bloodymodify(self, target, changes, controls=None, encode=True):
        """
		Performs the modify and modify_dn operation.
		
		:param target: The name of the object whose attributes are to be modified
		:type target: str
		:param changes: Describes the changes to be made on the object. Must be a dictionary of the following format: {'attribute': [('change_type', [value])]}
		:type changes: dict
		:param controls: additional controls to be passed in the query
		:type controls: dict
		:param encode: encode the changes provided before sending them to the server
    	:type encode: bool
		"""
        if controls is not None:
            t = []
            for control in controls:
                t.append(
                    {
                        "controlType": control[0].encode(),
                        "criticality": control[1],
                        "controlValue": control[2],
                    }
                )
            controls = t
        
        new_dn = ""
        attr_changes = {}
        for attr_name in changes:
            if attr_name.lower() == "distinguishedname":
                new_dn = changes[attr_name][0][1][0]
            else:
                attr_changes[attr_name] = changes[attr_name]
        target_dn = await self.dnResolver(target)
        if attr_changes:
            _, err = await self.modify(target_dn, attr_changes, controls, encode=encode)
            if err:
                raise err
        if new_dn:
            new_rdn, new_superior = new_dn.split(",", 1)
            old_rdn, old_superior = target_dn.split(",", 1)
            new_superior = new_superior if new_superior != old_superior else None
            _, err = await self._con.modify_dn(target_dn, new_rdn, newSuperior = new_superior)
            if err:
                raise err

    @cached_property
    def current_site(self):
        return (self._serverinfo["serverName"].rsplit(",CN=Sites")[0]).split(
            ",CN=Servers,CN="
        )[1]

    async def get_is_gc(self):
        # If we are in a gc connection we don't have the options attribute but we can check the scheme of our connection
        if self.conf.scheme == "gc":
            return True

        NTDSDSA_OPT_IS_GC = 1
        # Sometimes raise an error, I don't know why, maybe race condition?
        entry = None
        async for e in self.bloodysearch(self._serverinfo["dsServiceName"], attr=["options"]):
            entry = e
            break
        if entry:
            nTDSDSA_options = entry["options"]
            return nTDSDSA_options & NTDSDSA_OPT_IS_GC
        return False
    
    @property
    def is_gc(self):
        # Provide a synchronous property for backward compatibility where possible
        # This will be called from synchronous code that doesn't need the actual value
        return self.conf.scheme == "gc"

    async def get_policy(self):
        """
        [MS-ADTS] - 3.1.1.3.4.6 LDAP Policies
        """
        dict_policy = {"MaxPageSize": 1000}

        nTDSDSA_dn = self._serverinfo["dsServiceName"]
        site_match = re.search("[^,]+,CN=Sites.+", nTDSDSA_dn)
        nTDSSiteSettings_filter = ""
        if site_match:
            nTDSSiteSettings_dn = "CN=NTDS Site Settings," + site_match.group()
            nTDSSiteSettings_filter = f"(distinguishedName={nTDSSiteSettings_dn})"
        default_policy_dn = (
            "CN=Default Query Policy,CN=Query-Policies,CN=Directory"
            " Service,CN=Windows NT,CN=Services," + self.configNC
        )
        ldap_filter = f"(|(distinguishedName={nTDSDSA_dn}){nTDSSiteSettings_filter}(distinguishedName={default_policy_dn}))"
        raw_policy = ""

        async for entry, err in self.pagedsearch(
            ldap_filter, ["lDAPAdminLimits"], tree=self.configNC
        ):
            if err:
                raise err

            if "lDAPAdminLimits" not in entry:
                continue
            if entry["objectName"] == nTDSDSA_dn:
                raw_policy = entry["attributes"]["lDAPAdminLimits"]
                break
            elif entry["objectName"] == nTDSSiteSettings_dn:
                raw_policy = entry["attributes"]["lDAPAdminLimits"]
            elif not raw_policy and entry["objectName"] == default_policy_dn:
                raw_policy = entry["attributes"]["lDAPAdminLimits"]

        for raw_param in raw_policy:
            param_name, _, param_val = raw_param.partition("=")
            dict_policy[param_name] = int(param_val)

        return dict_policy

    async def getTrustMap(self, nctype=NCType.ALL):
        if self._trustmap and (self._nctype & nctype) == nctype:
            return self._trustmap
        await self.getTrusts(
            transitive=True,
            dns=self.conf.dns,
            allow_gc=(nctype == NCType.PARTIAL_DOM),
        )
        return self._trustmap

    async def interTrustOp(self, partition_map, op_params, op_name="bloodysearch"):
        async def partitionOp(conn_list):
            for conn in conn_list:
                try:
                    ldap = await conn.ldap
                    op_fn = getattr(ldap, op_name)
                    return op_fn(op_params)
                except Exception as e:
                    LOG.error(
                        f"Something went wrong when trying to perform '{op_name}' with '{op_params}' on {conn.conf.host} with the {conn.conf.scheme} protocol"
                    )
                    LOG.error(f"Error {type(e).__name__}: {e}")

        tasks = []
        for pattr in partition_map.values():
            tasks.append(partitionOp(pattr["conn_list"]))
        op_results = await asyncio.gather(*tasks)
        return op_results

    async def bloodysearch(
        self,
        base,
        ldap_filter="(objectClass=*)",
        search_scope=Scope.BASE,
        attr=None,
        control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
        ),
        controls=None,
        raw=False,
    ):
        # Because when calling badldap high-level functions it doesn't handle prettify so we call prettify only if ldap is used
        # (hoping badldap will not be called after)
        if self.is_prettified is False:
            formatters.enableFormatOutput()
            self.is_prettified = True
        # Handles corner case where querying default partitions (no dn provided for that)
        if base:
            base_dn = await self.dnResolver(base)
        else:
            base_dn = base

        if attr is None:
            attr = ["*"]

        # Build a local controls list to avoid mutating caller-provided lists
        local_controls = list(controls) if controls else []
        if control_flag:
            # Search control to request security descriptor parts
            req_flags = SDFlagsRequestValue({"Flags": control_flag})
            local_controls.append(("1.2.840.113556.1.4.801", True, req_flags.dump()))

        policy = await self.get_policy()
        self.ldap_query_page_size = policy["MaxPageSize"]
        search_generator = self.pagedsearch(
            ldap_filter,
            attr,
            tree=base_dn,
            search_scope=search_scope.value,
            controls=local_controls,
            raw=raw,
        )

        isNul = True
        try:
            async for entry, err in search_generator:
                if err:
                    raise err
                isNul = False
                yield {
                    **{"distinguishedName": entry["objectName"]},
                    **entry["attributes"],
                }
        finally:
            await search_generator.aclose()
        if isNul:
            raise NoResultError(base_dn, ldap_filter)

    async def getTrusts(self, transitive=False, dns="", allow_gc=True):
        # forest_name = ""
        # forest_name = (
        #     ".".join(conn.ldap._serverinfo["rootDomainNamingContext"].split(",DC="))
        # ).split("DC=")[1]

        # We shouldn't need to make trust_dict async_safe cause there is no call to trust_dict before an await access it in fetchTrusts()
        trust_dict = {}
        trust_to_explore = await self.fetchTrusts(
            self.conn, trust_dict, dns, allow_gc=allow_gc
        )

        # We don't do it on foreign trust because there is no transitivity between 3 forests (A<->B<->C) A doesn't have trust on C even if B has it
        if transitive:
            if not self.conf.domain:
                LOG.warning(
                    "No domain (-d, --domain) provided, transitive trust search will not be"
                    " performed"
                )
            elif self.conf.domain not in trust_dict:
                LOG.warning(
                    "User doesn't belong to this forest, transitive trust search will not be"
                    " performed"
                )
            else:
                LOG.info(
                    "Forest trusts fetched, performing transitive trust search"
                )
                tasks = []
                for domain_name, parent_conn in trust_to_explore.items():
                    tasks.append(
                        self.fetchTrusts(
                            parent_conn, trust_dict, dns, domain_name, allow_gc=allow_gc
                        )
                    )
                await asyncio.gather(*tasks)

        if not trust_dict:
            LOG.warning("No Trusts found")
        return trust_dict

    async def fetchTrusts(self, conn, trust_dict, dns, domain_name="", allow_gc=True):
        # Search request to look into all available domain partitions on the dc for trusts relationships
        # We don't care if because of simultaneous dc search there are duplicates, the overhead is minor, trusts are not many
        search_params = {
            "base": "",
            "ldap_filter": "(objectClass=trustedDomain)",
            "attr": [
                "trustDirection",
                "trustPartner",
                "trustAttributes",
                "trustType",
                "securityIdentifier",
            ],
            "search_scope": Scope.SUBTREE,
            "raw": True,
            "controls": [phantomRoot()],
        }
        trusts = await self.searchInForest(
            conn, search_params, dns, domain_name, allow_gc
        )
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

            # Let's not waste a run of fetchTrusts and keep active track of it so we can reuse it later
            self._trustmap[already_in_tree]["conn"] = trust["parent_conn"]
            self._trustmap[trust["trustPartner"][0].decode()]["domsid"] = str(
                dtyp.sid.SID.from_bytes(trust["securityIdentifier"][0])
            )

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

    async def searchInForest(
        self, conn, search_params, dns, domain_name="", allow_gc=True
    ):
        # If domain_name is provided it means we try to reach a domain outside of current "conn" forest so we have to find a server that we can reach for this outsider domain and then we search the entire forest related to this outsider domain
        newconn = conn
        if domain_name:
            ldap_conn = await newconn.getLdap()
            host_params = await reacher.findReachableDomainServer(
                domain_name,
                ldap_conn.current_site,
                server_type="" if allow_gc else "ldap",
                dns_addr=dns,
                dc_dns=newconn.conf.dcip,
            )
            if not host_params:
                LOG.warning(
                    f"No reachable server found for {domain_name}, try to provide one"
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
        newconn_ldap = await newconn.getLdap()
        if newconn_ldap.is_gc and allow_gc:
            search_results = await self.searchInPartition(
                newconn, search_params, dns, allow_gc=allow_gc
            )
            if newconn != conn and newconn._ldap:
                await newconn._ldap.close()
            return search_results

        # Find all domain partitions in the forest and dc hosting them
        try:
            # Get all domain partitions in the forest
            # partitions = conn.ldap.bloodysearch("CN=Partitions," + conn.ldap.configNC, "(&(objectClass=crossRef)(systemFlags=3))", attr=["nCName"])
            # Find nTDSDSA objects containing msDS-HasDomainNCs and server objects parents containing dNSHostname
            ldap_conn = await newconn.getLdap()
            entries = ldap_conn.bloodysearch(
                "CN=Sites," + ldap_conn.configNC,
                "(|(objectClass=nTDSDSA)(objectClass=server))",
                search_scope=Scope.SUBTREE,
                attr=["msDS-HasDomainNCs", "dNSHostName", "objectClass"],
            )
            # Put domain partitions and hostnames together by matching server distinguished name on them
            forest_servers = collections.defaultdict(dict)
            async for entry in entries:
                if "server" in entry["objectClass"]:
                    try:
                        forest_servers[entry["distinguishedName"]]["host"] = entry[
                            "dNSHostName"
                        ]
                    except KeyError:
                        LOG.warning(
                            f"No dNSHostName found for DC {entry['distinguishedName']}, the DC may have been demoted or have synchronization issues"
                        )
                else:
                    parent_name = (entry["distinguishedName"]).split(",", 1)[1]
                    try:
                        forest_servers[parent_name]["partitions"] = entry[
                            "msDS-HasDomainNCs"
                        ]
                    except:
                        print("There was some error here")

            # Reorganize dict on domain so domain becomes the key containing the hosts
            forest_partitions = collections.defaultdict(list)
            for dn, attributes in forest_servers.items():
                if "host" not in attributes:
                    LOG.warning(
                        f"No dNSHostName found for DC {dn}, the DC may have been demoted or have synchronization issues"
                    )
                for p in attributes.get("partitions"):
                    forest_partitions[p].append(
                        {"type": ["A", "AAAA"], "name": attributes["host"]}
                    )
            tasks = []
            for p, hosts in forest_partitions.items():
                host_list = hosts
                # if newconn already has this partition don't provide new hosts to connect to
                if p in ldap_conn._serverinfo["namingContexts"]:
                    host_list = []
                tasks.append(
                    self.searchInPartition(
                        newconn, search_params, dns, p, host_list, allow_gc=allow_gc
                    )
                )
            search_results = await asyncio.gather(*tasks)
            search_results = [entry for entries in search_results for entry in entries]
        except Exception as e:
            LOG.error(
                f"Something went wrong when trying to perform searchInForest for {domain_name}"
            )
            LOG.error(f"Error {type(e).__name__}: {e}")
        finally:
            if newconn != conn and newconn._ldap:
                await newconn._ldap.close()
            return search_results

    async def searchInPartition(
        self,
        conn,
        bloodysearch_params,
        dns,
        partition="",
        host_records=None,
        allow_gc=True,
    ):
        schemes = {389: "ldap", 636: "ldaps", 3268: "gc", 3269: "gc-ssl"}
        ports = [389, 636]
        if allow_gc:
            ports += [3268, 3269]
        # If host_records empty means the dc in "conn" is already the one we want to query
        if host_records:
            host_params = await reacher.findReachableServer(
                host_records, dns, conn.conf.dcip, ports=ports
            )
            if not host_params:
                LOG.warning(
                    f"No reachable server found for {partition}, try to provide one"
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
            newconn_ldap = await newconn.getLdap()
            if bloodysearch_params["base"] == "domainNC":
                # The directory can be handled by others instances of the function so we have to duplicate it before modifying it
                bloodysearch_params = dict(bloodysearch_params)
                bloodysearch_params["base"] = newconn_ldap.domainNC
            # We add parent_conn to know which conn has the trust, useful for krb cross realm
            search_result = [
                {"parent_conn": newconn, **entry}
                async for entry in newconn_ldap.bloodysearch(**bloodysearch_params)
            ]
        except Exception as e:
            LOG.error(
                f"Something went wrong when trying to perform this ldap search: {bloodysearch_params} on {newconn.conf.host} with the {newconn.conf.scheme} protocol"
            )
            LOG.error(f"Error {type(e).__name__}: {e}")
        finally:
            if newconn != conn and newconn._ldap:
                await newconn._ldap.close()
            return search_result


