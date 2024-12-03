from bloodyAD.formatters import accesscontrol
from bloodyAD.exceptions import NoResultError, TooManyResultsError, LOG
import re, os, enum, asyncio, threading, urllib
from functools import cached_property, lru_cache
from msldap.client import MSLDAPClient
from msldap.commons.factory import LDAPConnectionFactory
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue


class Scope(enum.Enum):
    BASE = 0
    LEVEL = 1
    SUBTREE = 2


class Change(enum.Enum):
    ADD = "add"
    DELETE = "delete"
    REPLACE = "replace"
    INCREMENT = "increment"


class Ldap(MSLDAPClient):
    conf = None
    domainNC = None
    configNC = None

    def __init__(self, cnf):
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

        if cnf.certificate:
            if cnf.certificate == "certstore":
                if os.name == "nt":
                    auth = "kerberos-certstore"
                else:
                    raise ValueError(
                        "Certstore only available on Windows, --certstore can't be left empty here"
                    )
            elif cnf.crt:
                auth = "ssl"
                params += "&sslcert=" + encoded_cnf["crt"]
                if cnf.key:
                    params += "&sslkey=" + encoded_cnf["key"]
                if cnf.password:
                    params += "&sslpassword=" + encoded_cnf["password"]
            else:
                raise ValueError(
                    "--certificate must have <cert_key>+':'+<cert> format, leave it empty to use the Windows certstore"
                )

        elif cnf.kerberos:
            username = "%s\\%s" % (encoded_cnf["domain"], encoded_cnf["username"])
            if cnf.dcip == cnf.host:
                raise ValueError(
                    "You can provide the IP in --dc-ip but you need to provide the"
                    " hostname in --host in order for kerberos to work"
                )
            params += "&dc=" + cnf.kdc
            if cnf.kdcc and cnf.realmc:
                params += f"&dcc={cnf.kdcc}&realmc={cnf.realmc}"

            if cnf.password:
                if cnf.format in ["aes", "rc4"]:
                    auth = "kerberos-" + cnf.format
                else:
                    auth = "kerberos-password"
                key = encoded_cnf["password"]
            else:
                key = encoded_cnf["key"]
                if not key:
                    if os.name == "nt":
                        auth = "sspi-kerberos"
                    else:
                        raise ValueError(
                            "You should provide a -p 'password' or a kerberos ticket"
                            " via '-k <keyfile_type>=./myticket'"
                        )
                else:
                    auth = "kerberos-" + cnf.krbformat
                    if cnf.format in ["b64", "hex"]:
                        auth += cnf.format

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

        auth = "+" + auth if auth else ""
        creds = username if username else ""
        creds = creds + ":" + key if key else creds
        creds = creds + "@" if creds else ""
        params = "/?" + params
        co_url = f"{cnf.scheme}{auth}://{creds}{encoded_cnf['host']}{params}"
        LOG.debug(f"[+] Connection URL: {co_url}")
        ldap_factory = LDAPConnectionFactory.from_url(co_url)
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
            LOG.debug(f"[*] Trying to connect to {cnf.host}...")
            _, err = asyncio.run_coroutine_threadsafe(
                getServerInfo(connect_task), self.loop
            ).result()
            if err:
                raise err
            LOG.debug("[+] Connection successful")
            self.domainNC = self._serverinfo["defaultNamingContext"]
            self.configNC = self._serverinfo["configurationNamingContext"]
            self.schemaNC = self._serverinfo["schemaNamingContext"]
            self.appNCs = []
            for nc in self._serverinfo["namingContexts"]:
                if nc == self.domainNC or nc == self.configNC or nc == self.schemaNC:
                    continue
                self.appNCs.append(nc)
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
        asyncio.run_coroutine_threadsafe(self.disconnect(), self.loop).result()
        self.closeThread()

    def bloodydelete(self, target, *args):
        _, err = asyncio.run_coroutine_threadsafe(
            self.delete(self.dnResolver(target), *args), self.loop
        ).result()
        if err:
            raise err

    @lru_cache
    def dnResolver(self, identity, objtype=None):
        """
        Return the DN for the object based on the parameters identity
        Args:
            identity: sAMAccountName, DN, GUID or SID of the user
            objtype: None is default or GPO
        """

        async def asyncDnResolver(identity, objtype=None):
            if "dc=" in identity.lower():
                # identity is a DN, return as is
                # We do not try to validate it because it could be from another trusted domain
                return identity

            if "s-1-" in identity.lower():
                # We assume identity is an SID
                ldap_filter = f"(objectSid={identity})"
            elif "{" in identity:
                if objtype == "GPO":
                    ldap_filter = (
                        f"(&(objectClass=groupPolicyContainer)(name={identity}))"
                    )
                else:
                    # We assume identity is a GUID
                    ldap_filter = f"(objectGUID={identity})"
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
                raise NoResultError(self.domainNC, ldap_filter)

            return dn

        return asyncio.run_coroutine_threadsafe(
            asyncDnResolver(identity, objtype), self.loop
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

    def bloodysearch(
        self,
        base,
        ldap_filter="(objectClass=*)",
        search_scope=Scope.BASE,
        attr=["*"],
        control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
        ),
        controls=None,
        op_attr=False,
        raw=False,
    ):
        # Handles corner case where querying default partitions (no dn provided for that)
        if base:
            base_dn = self.dnResolver(base)
        else:
            base_dn = base

        if not controls:
            # Search control to request security descriptor parts
            req_flags = SDFlagsRequestValue({"Flags": control_flag})
            controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

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
