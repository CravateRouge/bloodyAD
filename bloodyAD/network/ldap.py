from bloodyAD.formatters import accesscontrol, common
from bloodyAD.exceptions import NoResultError, TooManyResultsError, LOG
import re, os, enum, asyncio, threading, urllib, collections, ssl
from functools import cached_property, lru_cache
from asn1crypto import core
from dns import resolver, rdatatype
from msldap.client import MSLDAPClient
from msldap.commons.factory import LDAPConnectionFactory
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue
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
    dc_domain = None

    def __init__(self, conn):
        self._trustmap = collections.defaultdict(dict)
        self.conn = conn
        cnf = conn.conf
        self.conf = cnf

        # Because msldap uses a url format we have to encode everything properly
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
                    LOG.warning("[!] No .pem/.pfx extension detected, will try .pem")
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
            params += "&timeout=" + cnf.timeout

        auth = "+" + auth if auth else ""
        creds = username if username else ""
        creds = creds + ":" + key if key else creds
        creds = creds + "@" if creds else ""
        params = "/?" + params
        self.co_url = f"{cnf.scheme}{auth}://{creds}{encoded_cnf['host']}{params}"
        LOG.debug(f"[+] Connection URL: {self.co_url}")
        ldap_factory = LDAPConnectionFactory.from_url(self.co_url)
        super().__init__(ldap_factory.target, ldap_factory.credential, keepalive=True)

        # Connect function runs indefinitely waiting for I/O events so using asyncio.run will not allow us to reuse the connection
        # To avoid it, we launch it in another thread and we control it using a defined event_loop
        self.loop = asyncio.new_event_loop()
        connect_task = self.loop.create_task(self.connect())
        self.thread = threading.Thread(target=self.loop.run_forever)
        self.thread.start()

        # Using an async function to await connect_task because connect_task.result doesn't work
        async def getServerInfo(task):
            return await task

        try:
            LOG.debug(f"[*] Trying to connect to {self.conf.host}...")
            _, err = asyncio.run_coroutine_threadsafe(
                getServerInfo(connect_task), self.loop
            ).result()
            if err:
                raise err
            LOG.debug("[+] Connection successful")
            self.isactive = True
            self.domainNC = self._serverinfo["defaultNamingContext"]
            self.configNC = self._serverinfo["configurationNamingContext"]
            self.schemaNC = self._serverinfo["schemaNamingContext"]
            self.appNCs = []
            for nc in self._serverinfo["namingContexts"]:
                if nc in [self.domainNC, self.configNC, self.schemaNC]:
                    continue
                self.appNCs.append(nc)
            self.dc_domain = ('.'.join(self.domainNC.split(",DC="))).split("DC=")[1]
        except Exception as e:
            self.closeThread()
            raise e

    def bloodyadd(self, target, **kwargs):
        _, err = asyncio.run_coroutine_threadsafe(
            self.add(self.dnResolver(target), **kwargs), self.loop
        ).result()
        if err:
            raise err

    def closeThread(self):
        for task in asyncio.all_tasks(self.loop):
            task.cancel()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(0)

    def close(self):
        if not self.isactive:
            return
        self.isactive = False
        for trust in self._trustmap.values():
            if "conn" in trust and trust["conn"] != self.conn:
                trust["conn"].closeLdap()
        asyncio.run_coroutine_threadsafe(self.disconnect(), self.loop).result()
        self.closeThread()

    def bloodydelete(self, target, *args):
        _, err = asyncio.run_coroutine_threadsafe(
            self.delete(self.dnResolver(target), *args), self.loop
        ).result()
        if err:
            raise err

    @lru_cache
    def dnResolver(self, identity):
        """
        Return the DN for the object based on the parameters identity
        Args:
            identity: sAMAccountName, DN, GPO name or SID of the object
        """

        async def asyncDnResolver(identity):
            if ",dc=" in identity.lower():
                # identity is a DN, return as is
                # We do not try to validate it because it could be from another trusted domain
                return identity

            if identity.lower().startswith("s-1-"):
                # We assume identity is an SID
                ldap_filter = f"(objectSid={identity})"
            # For GPO name as GPO has no sAMAccountName
            elif identity.startswith("{"):
                ldap_filter = (
                    f"(name={identity})"
                )
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
                        f"[!] No results found for '{identity}' but found entries that could match: {anr_dn}"
                    )
                raise NoResultError(self.domainNC, ldap_filter)

            return dn

        return asyncio.run_coroutine_threadsafe(
            asyncDnResolver(identity), self.loop
        ).result()

    def bloodymodify(self, target, changes, controls=None, encode=True):
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

        _, err = asyncio.run_coroutine_threadsafe(
            self.modify(self.dnResolver(target), changes, controls, encode=encode),
            self.loop,
        ).result()
        if err:
            raise err

    @cached_property
    def current_site(self):
        return (self._serverinfo["serverName"].rsplit(",CN=Sites")[0]).split(
            ",CN=Servers,CN="
        )[1]

    @cached_property
    def is_gc(self):
        # If we are in a gc connection we don't have the options attribute but we can check the scheme of our connection
        if self.conf.scheme == "gc":
            return True

        NTDSDSA_OPT_IS_GC = 1
        # Sometimes raise an error, I don't know why, maybe race condition?
        nTDSDSA_options = next(
            self.bloodysearch(self._serverinfo["dsServiceName"], attr=["options"])
        )["options"]
        return nTDSDSA_options & NTDSDSA_OPT_IS_GC

    @cached_property
    def policy(self):
        """
        [MS-ADTS] - 3.1.1.3.4.6 LDAP Policies
        """

        async def asyncPolicy():
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

        return asyncio.run_coroutine_threadsafe(asyncPolicy(), self.loop).result()

    def getTrustMap(self, nctype=NCType.ALL):
        if self._trustmap and (self._nctype & nctype) == nctype:
            return self._trustmap
        asyncio.get_event_loop().run_until_complete(
            self.getTrusts(
                transitive=True,
                dns=self.conf.dns,
                allow_gc=(nctype == NCType.PARTIAL_DOM),
            )
        )
        return self._trustmap

    async def interTrustOp(self, partition_map, op_params, op_name="bloodysearch"):
        async def partitionOp(conn_list):
            for conn in conn_list:
                try:
                    op_fn = getattr(conn.ldap, op_name)
                    return op_fn(op_params)
                except Exception as e:
                    LOG.error(
                        f"[!] Something went wrong when trying to perform '{op_name}' with '{op_params}' on {conn.conf.host} with the {conn.conf.scheme} protocol"
                    )
                    LOG.error(f"[!] Error {type(e).__name__}: {e}")

        tasks = []
        for pattr in partition_map.values():
            tasks.append(partitionOp(pattr["conn_list"]))
        op_results = await asyncio.gather(*tasks)
        return op_results

    def bloodysearch(
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
        # Handles corner case where querying default partitions (no dn provided for that)
        if base:
            base_dn = self.dnResolver(base)
        else:
            base_dn = base

        if attr is None:
            attr = ["*"]

        if control_flag:
            # Search control to request security descriptor parts
            req_flags = SDFlagsRequestValue({"Flags": control_flag})
            if controls is None:
                controls = []
            controls.append(("1.2.840.113556.1.4.801", True, req_flags.dump()))

        self.ldap_query_page_size = self.policy["MaxPageSize"]
        search_generator = self.pagedsearch(
            ldap_filter,
            attr,
            tree=base_dn,
            search_scope=search_scope.value,
            controls=controls,
            raw=raw,
        )

        isNul = True
        try:
            while True:
                entry, err = asyncio.run_coroutine_threadsafe(
                    search_generator.__anext__(), self.loop
                ).result()
                if err:
                    raise err
                isNul = False
                yield {
                    **{"distinguishedName": entry["objectName"]},
                    **entry["attributes"],
                }
        except StopAsyncIteration:
            pass
        finally:
            asyncio.run_coroutine_threadsafe(
                search_generator.aclose(), self.loop
            ).result()
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
                    "[!] No domain (-d, --domain) provided, transitive trust search will not be"
                    " performed"
                )
            elif self.conf.domain not in trust_dict:
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
                    tasks.append(
                        self.fetchTrusts(
                            parent_conn, trust_dict, dns, domain_name, allow_gc=allow_gc
                        )
                    )
                await asyncio.gather(*tasks)

        if not trust_dict:
            LOG.warning("[!] No Trusts found")
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
            host_params = await findReachableDomainServer(
                domain_name,
                newconn.ldap.current_site,
                server_type="" if allow_gc else "ldap",
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
            search_results = await self.searchInPartition(
                newconn, search_params, dns, allow_gc=allow_gc
            )
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
                attr=["msDS-HasDomainNCs", "dNSHostName", "objectClass"],
            )
            # Put domain partitions and hostnames together by matching server distinguished name on them
            forest_servers = collections.defaultdict(dict)
            for entry in entries:
                if "server" in entry["objectClass"]:
                    try:
                        forest_servers[entry["distinguishedName"]]["host"] = entry[
                            "dNSHostName"
                        ]
                    except KeyError:
                        LOG.warning(
                            f"[!] No dNSHostName found for DC {entry['distinguishedName']}, the DC may have been demoted or have synchronization issues"
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
                        f"[!] No dNSHostName found for DC {dn}, the DC may have been demoted or have synchronization issues"
                    )
                for p in attributes.get("partitions"):
                    forest_partitions[p].append(
                        {"type": ["A", "AAAA"], "name": attributes["host"]}
                    )
            tasks = []
            for p, hosts in forest_partitions.items():
                host_list = hosts
                # if newconn already has this partition don't provide new hosts to connect to
                if p in newconn.ldap._serverinfo["namingContexts"]:
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
                f"[!] Something went wrong when trying to perform searchInForest for {domain_name}"
            )
            LOG.error(f"[!] Error {type(e).__name__}: {e}")
        finally:
            if newconn != conn and newconn._ldap:
                newconn.ldap.close()
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
            host_params = await findReachableServer(
                host_records, dns, conn.conf.dcip, ports=ports
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
            # We add parent_conn to know which conn has the trust, useful for krb cross realm
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


# Find LDAP or GC server based on current AD site
async def findReachableDomainServer(
    domain_or_forest_name, ad_site, server_type="", dns_addr="", dc_dns=""
):
    record_list = []
    ports = []
    if not server_type or server_type == "gc":
        record_list += [
            {
                "type": ["SRV"],
                "name": f"_gc._tcp.{ad_site}._sites.{domain_or_forest_name}",
            },
            {"type": ["SRV"], "name": f"_gc._tcp.{domain_or_forest_name}"},
        ]
        ports += [3268, 3269]
    if not server_type or server_type == "ldap":
        record_list += [
            {
                "type": ["SRV"],
                "name": f"_ldap._tcp.{ad_site}._sites.{domain_or_forest_name}",
            },
            {"type": ["SRV"], "name": f"_ldap._tcp.{domain_or_forest_name}"},
        ]
        ports += [389, 636]
    host_params = await findReachableServer(record_list, dns_addr, dc_dns, ports)
    return host_params


# Do 389 even for GC because more probabilities to bypass fw
# 389 LDAP, 636 LDAPS, 3268 GC, 3269 GCS
async def findReachableServer(
    record_list, dns_addr="", dc_dns="", ports=None
):
    if ports is None:
        ports = [389, 636, 3268, 3269]
    nameservers = [] + (resolver.get_default_resolver()).nameservers
    if dc_dns:
        nameservers = [dc_dns] + nameservers
    if dns_addr:
        nameservers = [dns_addr] + nameservers
    LOG.debug(f"[+] Nameservers set to: {nameservers}")

    # Try to find a dc where we can connect asap
    resolve_tasks = []
    for ns in nameservers:
        for r in record_list:
            resolve_tasks.append(
                asyncio.create_task(asyncResolveAndConnect(ns, r, ports))
            )

    host_params = await wait_first(resolve_tasks)
    return host_params


# Try to reach a host by first resolving its IPv4 or v6 by providing a nameserver and SRV, A or AAAA records
# Then trying to do a tcp connect on all hosts found, first answering will be returned
async def asyncResolveAndConnect(ns, r, ports):
    custom_resolver = resolver.Resolver()
    custom_resolver.nameservers = [ns]
    target_srvs = collections.defaultdict(list)
    answer = None
    LOG.debug(f"[*] Resolving {r}...")
    for rtype in r["type"]:
        try:
            answer = custom_resolver.resolve(r["name"], rtype, tcp=True)
            # SRV records
            if answer.rdtype == rdatatype.SRV:
                # Try to get IPs from additional part of the answer if there is one
                for raddi in answer.response.additional:
                    if raddi.rdtype in [rdatatype.A, rdatatype.AAAA]:
                        for raddr in raddi:
                            target_srvs[str(raddi.name)].append(raddr.address)
                # If no additional part we have to make other queries
                if not target_srvs:
                    for rsrv in answer:
                        for rsrv_type in ["A", "AAAA"]:
                            try:
                                target_srvs[rsrv.target.to_text()] += [
                                    rdata.address
                                    for rdata in custom_resolver.resolve(
                                        rsrv.target.to_text(), rsrv_type, tcp=True
                                    )
                                ]
                            except Exception as e:
                                LOG.debug(
                                    f"[!] Failed to resolve {rsrv.target.to_text()} {rsrv_type} with nameserver {ns}: {e}"
                                )
                                continue
            # A and AAAA records
            else:
                target_srvs[r["name"]] += [raddr.address for raddr in answer]

        except Exception as e:
            LOG.debug(
                f"[!] Failed to resolve {r['name']} {rtype} with nameserver {ns}: {e}"
            )
            continue

    # If the function failed to find hosts
    if not target_srvs:
        return {}

    # We try every combination of ips/ports, useful if there are firewalls
    # And we take the first to answer, we need only one having the replicas we need
    connect_tasks = []
    for port in ports:
        for target_ips in target_srvs.values():
            for ip in target_ips:
                connect_tasks.append(asyncio.create_task(host_connect(ip, port)))

    host_params = await wait_first(connect_tasks)
    # Function couldn't reach a host for this record
    if not host_params:
        return {}

    for name, ips in target_srvs.items():
        if host_params["ip"] in ips:
            if name.endswith("."):
                name = name.rstrip(".")
            host_params["name"] = name
            break
    return host_params


async def host_connect(ip, port):
    # Even if a dc doesn't support tls with ldap/gc it will accept the tcp connection
    # so we start a tls handshake on those port to be sure it handles tls
    ssl_context = None
    if port in [636, 3269]:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    try:
        LOG.debug(f"[*] Attempting to TCP connect to {ip}:{port}")
        reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_context)
        writer.close()
        await writer.wait_closed()
        return {"ip": ip, "port": port}
    except:
        LOG.debug(f"[!] Could not TCP connect to {ip}:{port}")
        return {}


async def wait_first(tasks):
    while tasks:
        finished, unfinished = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for x in finished:
            result = x.result()
            if result:
                if unfinished:
                    # cancel the other tasks, we have a result. We need to wait for the cancellations
                    # to propagate.
                    LOG.debug(f"[*] Cancelling {len(unfinished)} remaining tasks")
                    for task in unfinished:
                        task.cancel()
                    await asyncio.wait(unfinished)
                return result
        tasks = unfinished
    return
