from bloodyAD.patch import ldap3_patch
from bloodyAD.formatters import formatters, accesscontrol, helpers
from bloodyAD.formatters.formatters import (
    formatFunctionalLevel,
    formatGMSApass,
    formatSD,
    formatSchemaVersion,
    formatAccountControl,
    formatDnsRecord,
    formatKeyCredentialLink,
    formatWellKnownObjects,
)
from bloodyAD.exceptions import NoResultError, TooManyResultsError, BloodyError
import re, ssl
from functools import cached_property, lru_cache
import ldap3
from ldap3.protocol.formatters.formatters import format_sid, format_uuid_le


class Ldap(ldap3.Connection):
    conf = None
    domainNC = None
    configNC = None

    def __init__(self, cnf):
        self.conf = cnf
        ldap_server_kwargs = {
            "host": cnf.url,
            "get_info": ldap3.ALL,
            "formatter": {
                "nTSecurityDescriptor": formatSD,
                "msDS-AllowedToActOnBehalfOfOtherIdentity": formatSD,
                "msDS-Behavior-Version": formatFunctionalLevel,
                "objectVersion": formatSchemaVersion,
                "userAccountControl": formatAccountControl,
                "msDS-ManagedPassword": formatGMSApass,
                "msDS-GroupMSAMembership": formatSD,
                "dnsRecord": formatDnsRecord,
                "msDS-KeyCredentialLink": formatKeyCredentialLink,
                "tokenGroups": format_sid,
                "tokenGroupsNoGCAcceptable": format_sid,
                "wellKnownObjects": formatWellKnownObjects,
                "schemaIDGUID": format_uuid_le,
                "attributeSecurityGUID": format_uuid_le,
            },
        }
        ldap_connection_kwargs = {"raise_exceptions": True, "auto_range": True}

        if cnf.crt:
            key = cnf.key if cnf.key else None
            tls = ldap3.Tls(
                local_private_key_file=key,
                local_certificate_file=cnf.crt,
                validate=ssl.CERT_NONE,
            )
            ldap_server_kwargs["tls"] = tls
            if cnf.scheme != "ldaps":
                ldap_connection_kwargs.update({
                    "authentication": ldap3.SASL,
                    "sasl_mechanism": ldap3.EXTERNAL,
                    "auto_bind": ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                })
        elif cnf.kerberos:
            ldap_connection_kwargs.update({
                "authentication": ldap3.SASL,
                "sasl_mechanism": ldap3.KERBEROS,
            })
            if cnf.scheme != "ldaps":
                ldap_connection_kwargs.update({"session_security": "ENCRYPT"})

        else:
            ldap_connection_kwargs.update({
                "user": "%s\\%s" % (cnf.domain, cnf.username),
                "password": cnf.password,
                "authentication": ldap3.NTLM,
            })
            if cnf.scheme != "ldaps":
                ldap_connection_kwargs.update({"session_security": "ENCRYPT"})

        s = ldap3.Server(**ldap_server_kwargs)
        super().__init__(s, **ldap_connection_kwargs)
        if cnf.crt and cnf.scheme == "ldaps":
            self.open()
        else:
            self.bind()

        helpers.ldap_conn = self

        self.domainNC = self.server.info.other["defaultNamingContext"][0]
        self.configNC = self.server.info.other["configurationNamingContext"][0]
        self.schemaNC = self.server.info.other["schemaNamingContext"][0]
        self.appNCs = []
        for nc in self.server.info.naming_contexts:
            if nc == self.domainNC or nc == self.configNC or nc == self.schemaNC:
                continue
            self.appNCs.append(nc)

    def bloodyadd(self, target, **kwargs):
        self.add(self.dnResolver(target), **kwargs)
        if self.result["description"] != "success":
            raise BloodyError(self.result["description"])

    def bloodydelete(self, target, *args):
        self.delete(self.dnResolver(target), *args)

    @lru_cache
    def dnResolver(self, identity, objtype=None):
        """
        Return the DN for the object based on the parameters identity
        Args:
            identity: sAMAccountName, DN, GUID or SID of the user
            objtype: None is default or GPO
        """
        if "dc=" in identity.lower():
            # identity is a DN, return as is
            # We do not try to validate it because it could be from another trusted domain
            return identity

        if "s-1-" in identity.lower():
            # We assume identity is an SID
            ldap_filter = f"(objectSid={identity})"
        elif "{" in identity:
            if objtype == "GPO":
                ldap_filter = f"(&(objectClass=groupPolicyContainer)(name={identity}))"
            else:
                # We assume identity is a GUID
                ldap_filter = f"(objectGUID={identity})"
        else:
            # By default, we assume identity is a sam account name
            ldap_filter = f"(sAMAccountName={identity})"

        super().search(self.domainNC, ldap_filter)
        dn = ""
        for entry in self.entries:
            if dn:
                raise TooManyResultsError(self.domainNC, ldap_filter, self.entries)
            dn = entry.entry_dn

        if not dn:
            raise NoResultError(self.domainNC, ldap_filter)

        return dn

    def bloodymodify(self, target, *args):
        self.modify(self.dnResolver(target), *args)
        if self.result["description"] != "success":
            raise BloodyError(self.result["description"])

    @cached_property
    def policy(self):
        """
        [MS-ADTS] - 3.1.1.3.4.6 LDAP Policies
        """
        dict_policy = {"MaxPageSize": 1000}

        nTDSDSA_dn = self.server.info.other["dsServiceName"][0]
        site_match = re.search("[^,]+,CN=Sites.+", nTDSDSA_dn)
        nTDSSiteSettings_filter = ""
        if site_match:
            nTDSSiteSettings_dn = "CN=NTDS Site Settings," + site_match.group()
            nTDSSiteSettings_filter = f"(distinguishedName={nTDSSiteSettings_dn})"
        default_policy_dn = (
            "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows"
            " NT,CN=Services,"
            + self.configNC
        )

        ldap_filter = f"(|(distinguishedName={nTDSDSA_dn}){nTDSSiteSettings_filter}(distinguishedName={default_policy_dn}))"
        raw_policy = ""
        super().search(self.configNC, ldap_filter, attributes=["lDAPAdminLimits"])
        for entry in self.entries:
            if "lDAPAdminLimits" not in entry:
                continue

            if entry.entry_dn == nTDSDSA_dn:
                raw_policy = entry["lDAPAdminLimits"]
                break
            elif entry.entry_dn == nTDSSiteSettings_dn:
                raw_policy = entry["lDAPAdminLimits"]
            elif not raw_policy and entry.entry_dn == default_policy_dn:
                raw_policy = entry["lDAPAdminLimits"]

        for raw_param in raw_policy:
            param_name, _, param_val = raw_param.partition("=")
            dict_policy[param_name] = int(param_val)

        return dict_policy

    def bloodysearch(
        self,
        base,
        ldap_filter="(objectClass=*)",
        search_scope=ldap3.BASE,
        attr=["*"],
        control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
        ),
        controls=None,
        op_attr=False,
        generator=False,
        raw=False,
    ):
        # Handles corner case where querying default partitions (no dn provided for that)
        if base:
            base_dn = self.dnResolver(base)
        else:
            base_dn = base

        if not controls:
            controls = ldap3.protocol.microsoft.security_descriptor_control(
                sdflags=control_flag
            )

        entries = self.extend.standard.paged_search(
            base_dn,
            ldap_filter,
            search_scope=search_scope,
            attributes=attr,
            dereference_aliases=ldap3.DEREF_NEVER,
            get_operational_attributes=op_attr,
            paged_size=self.policy["MaxPageSize"],
            controls=controls,
            generator=generator,
        )

        attrtype = "raw_attributes" if raw else "attributes"
        dntype = "raw_dn" if raw else "dn"
        isNul = True
        for entry in entries:
            if attrtype not in entry:
                continue
            isNul = False
            yield {**{"distinguishedName": entry[dntype]}, **entry[attrtype]}
        if isNul:
            raise NoResultError(base_dn, ldap_filter)
