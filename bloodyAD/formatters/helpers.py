import uuid

ldap_conn = None


def ldap_search(base_dn, filter, attr):
    try:
        if (
            not ldap_conn.search(base_dn, filter, attributes=attr)
            or not len(ldap_conn.entries)
            or attr not in ldap_conn.entries[0]
        ):
            return None
    except:
        return None

    return ldap_conn.entries[0][attr].value


def resolveSid(sid):
    r = ldap_search(
        "CN=WellKnown Security"
        f" Principals,{ldap_conn.server.info.other['configurationNamingContext'][0]}",
        f"(objectSid={sid})",
        "name",
    )
    if r:
        return r
    r = ldap_search(
        ldap_conn.server.info.other["rootDomainNamingContext"][0],
        f"(objectSid={sid})",
        "sAMAccountName",
    )
    return r if r else sid


def resolveGUID(guid_raw):
    attr = "name"
    guid_canonical = str(uuid.UUID(bytes_le=guid_raw))
    guid_str = "\\" + "\\".join(["{:02x}".format(b) for b in guid_raw])
    schema_dn = ldap_conn.server.info.other["schemaNamingContext"][0]
    r = ldap_search(
        f"CN=Extended-Rights,{ldap_conn.server.info.other['configurationNamingContext'][0]}",
        f"(rightsGuid={guid_canonical})",
        attr,
    )
    if not r:
        r = ldap_search(schema_dn, f"(schemaIDGUID={guid_str})", attr)
        return r if r else guid_canonical
    if not ldap_conn.search(
        schema_dn, f"(attributeSecurityGUID={guid_str})", attributes=attr
    ) or not len(ldap_conn.entries):
        return r
    return {r: [entry[attr].value for entry in ldap_conn.entries]}
