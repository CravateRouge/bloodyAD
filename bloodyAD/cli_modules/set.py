import msldap

from bloodyAD import utils
from bloodyAD.exceptions import LOG
from bloodyAD.formatters import accesscontrol
from bloodyAD.network.ldap import Change, Scope
from msldap.protocol import typeconversion
from msldap.protocol.typeconversion import (
    LDAP_WELL_KNOWN_ATTRS,
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES,
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC
)
from datetime import datetime, timezone, timedelta
import unicodedata



def object(conn, target: str, attribute: str, v: list = [], raw: bool = False):
    """
    Add/Replace/Delete target's attribute

    :param target: sAMAccountName, DN or SID of the target
    :param attribute: name of the attribute
    :param v: add value if attribute doesn't exist, replace value if attribute exists, delete if no value given, can be called multiple times if multiple values to set (e.g -v HOST/janettePC -v HOST/janettePC.bloody.local)
    :param raw: if set, will try to send the values provided as is, without any encoding
    """
    if not raw:
        # We change some encoding functions because for whatever reason some are marked as 'bytes' but are actually 'sd' so can take sddl string
        # but we cannot directly change in msldap because it would break the ones passing directly multi_bytes
        MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC["msDS-AllowedToActOnBehalfOfOtherIdentity"] = typeconversion.multi_sd
        MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC["nTSecurityDescriptor"] = typeconversion.single_sd
        norm_attr = attribute.lower()
        lookup_table = None
        # Order is very important cause there are overlapped with different encoding function values
        for table in [MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC, MSLDAP_BUILTIN_ATTRIBUTE_TYPES, LDAP_WELL_KNOWN_ATTRS]:
            for key in table:
                if key.lower() == norm_attr:
                    attribute = key
                    lookup_table = table
                    break
            if lookup_table:
                break

        if lookup_table:
            encoding_func = lookup_table[attribute]
            str_support = ["utf16le","sid","str","int","guid","sd"]
            encoding_type = encoding_func.__name__.split('_')[1]
            if encoding_type not in str_support:
                LOG.warning(f"[!] Attribute encoding not supported for {attribute} with {encoding_type} attribute type, using raw mode")
                raw = True
        else:
            LOG.warning(f"[!] Attribute encoding not supported for {attribute}, using raw mode")
            raw = True
    # Converting raw str into raw binary
    if raw:
        v = [vstr.encode() for vstr in v]

    conn.ldap.bloodymodify(
        target, {attribute: [(Change.REPLACE.value, v)]}, encode=(not raw)
    )
    LOG.info(f"[+] {target}'s {attribute} has been updated")


def owner(conn, target: str, owner: str):
    """
    Changes target ownership with provided owner (WriteOwner permission required)

    :param target: sAMAccountName, DN or SID of the target
    :param owner: sAMAccountName, DN or SID of the new owner
    """
    new_sid = next(conn.ldap.bloodysearch(owner, attr=["objectSid"]))["objectSid"]

    new_sd, _ = utils.getSD(
        conn, target, "nTSecurityDescriptor", accesscontrol.OWNER_SECURITY_INFORMATION
    )

    old_sid = new_sd["OwnerSid"].formatCanonical()
    if old_sid == new_sid:
        LOG.warning(f"[!] {old_sid} is already the owner, no modification will be made")
    else:
        new_sd["OwnerSid"].fromCanonical(new_sid)

        req_flags = msldap.wintypes.asn1.sdflagsrequest.SDFlagsRequestValue(
            {"Flags": accesscontrol.OWNER_SECURITY_INFORMATION}
        )
        controls = [("1.2.840.113556.1.4.801", True, req_flags.dump())]

        conn.ldap.bloodymodify(
            target,
            {"nTSecurityDescriptor": [(Change.REPLACE.value, new_sd.getData())]},
            controls,
        )

        LOG.info(f"[+] Old owner {old_sid} is now replaced by {owner} on {target}")


# Full info on what you can do:
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/change-windows-active-directory-user-password
def password(conn, target: str, newpass: str, oldpass: str = None):
    """
    Change password of a user/computer

    :param target: sAMAccountName, DN or SID of the target
    :param newpass: new password for the target
    :param oldpass: old password of the target, mandatory if you don't have "change password" permission on the target
    """
    encoded_new_password = '"%s"' % newpass
    if oldpass is not None:
        encoded_old_password = '"%s"' % oldpass
        op_list = [
            (Change.DELETE.value, encoded_old_password),
            (Change.ADD.value, encoded_new_password),
        ]
    else:
        op_list = [(Change.REPLACE.value, encoded_new_password)]

    try:
        conn.ldap.bloodymodify(target, {"unicodePwd": op_list})

    except msldap.commons.exceptions.LDAPModifyException as e:
        # Let's check if we comply to pwd policy
        entry = next(
            conn.ldap.bloodysearch(
                target,
                attr=[
                    "msDS-ResultantPSO",
                    "pwdLastSet",
                    "displayName",
                    "sAMAccountName",
                    "sAMAccountType",
                ],
            )
        )
        pwdLastSet = entry.get("pwdLastSet", 0)
        pwdPolicy = None
        error_str = ""
        if "msDS-ResultantPSO" in entry:
            tmpPolicy = next(
                conn.ldap.bloodysearch(
                    entry["msDS-ResultantPSO"],
                    attr=[
                        "msDS-MinimumPasswordAge",
                        "msDS-MinimumPasswordLength",
                        "msDS-PasswordHistoryLength",
                        "msDS-PasswordComplexityEnabled",
                        "name",
                    ],
                )
            )
            pwdPolicy = {
                "minPwdAge": tmpPolicy.get("msDS-MinimumPasswordAge", timedelta()),
                "minPwdLength": tmpPolicy.get("msDS-MinimumPasswordLength", 0),
                "pwdHistoryLength": tmpPolicy.get("msDS-PasswordHistoryLength", 0),
                "pwdComplexity": tmpPolicy.get("msDS-PasswordComplexityEnabled", False),
            }
            # custom password policies are not readable by basic users
            if "name" not in tmpPolicy:
                error_str = (
                    "Password can't be changed. User is subject to the custom password"
                    f" policy {entry['msDS-ResultantPSO'].split(',')[0]} which may be"
                    " more restrictive than the default one."
                )
        else:
            pwdPolicy = next(
                conn.ldap.bloodysearch(
                    conn.ldap.domainNC,
                    attr=[
                        "minPwdAge",
                        "minPwdLength",
                        "pwdHistoryLength",
                        "pwdProperties",
                    ],
                )
            )
            pwdPolicy["pwdComplexity"] = (pwdPolicy["pwdProperties"] & 1) > 0

        # Complexity check
        if pwdPolicy.get("pwdComplexity"):
            tmp_err = "New password doesn't match the complexity:"
            objectName = entry["sAMAccountName"]
            objectDisplayName = entry.get("displayName", "")
            # Checks on name only apply on users not computers idk why
            if (
                entry["sAMAccountType"] == 805306368
                and objectName.upper() in newpass.upper()
            ):
                error_str = (
                    f"{tmp_err} newpass must not include the user's name '{objectName}'"
                    " (case insensitive)."
                )
            elif (
                entry["sAMAccountType"] == 805306368
                and objectDisplayName
                and objectDisplayName.upper() in newpass.upper()
            ):
                error_str = (
                    f"{tmp_err} newpass must not include the user's display name"
                    f" '{objectDisplayName}' (case insensitive)."
                )
            else:
                checks = 0
                if any(char.isupper() for char in newpass):
                    checks += 1
                if any(char.islower() for char in newpass):
                    checks += 1
                if any(char.isdigit() for char in newpass):
                    checks += 1
                if any(char in '-!"#$%&()*,./:;?@[]^_`{|}~+<=>' for char in newpass):
                    checks += 1
                # Any Unicode character that's categorized as an alphabetic character but isn't uppercase or lowercase
                # https://www.unicode.org/reports/tr44/#General_Category_Values
                if any(
                    "L" in unicodedata.category(char)
                    and unicodedata.category(char) not in ["Ll", "Lu"]
                    for char in newpass
                ):
                    checks += 1

                if checks < 3:
                    error_str = (
                        f"{tmp_err} The password must contains characters from three of"
                        " the following categories: Uppercase, Lowercase, Digits,"
                        " Special, Unicode Alphabetic not included in Uppercase and"
                        " Lowercase"
                    )
        # Pwd length check
        if len(newpass) < pwdPolicy.get("minPwdLength", 0):
            error_str += (
                "\nNew password should have at least"
                f" {pwdPolicy['minPwdLength']} characters and not {len(newpass)}"
            )
        # Pwd age check
        if pwdLastSet:
            pwdAge = datetime.now(timezone.utc) - pwdLastSet
            if pwdAge < -pwdPolicy.get("minPwdAge", timedelta()):
                error_str += (
                    "\nPassword can't be changed before"
                    f" {pwdPolicy['minPwdAge'] - pwdAge} because of the minimum"
                    " password age policy."
                )
        # No issue has been found, it may be because of the password history
        if not error_str:
            # If password changed without oldpass, you don't need to respect password history
            if not oldpass:
                error_str = (
                    "Password can't be changed. It may be because the oldpass provided"
                    " is not valid.\nYou can try to use another password change"
                    " protocol such as smbpasswd, server error may be more explicit."
                )
            else:

                if pwdPolicy.get("pwdHistoryLength", 0) > 0:
                    if oldpass == newpass:
                        error_str = "New Password can't be identical to old password."
                    else:
                        error_str = (
                            "Password can't be changed. It may be because the new"
                            " password is already in the password history of the"
                            " target or that the oldpass provided is not valid.\nYou"
                            " can try to use another password change protocol such as"
                            " smbpasswd, server error may be more explicit."
                        )
                else:
                    error_str = (
                        "Password can't be changed. It may be because the oldpass"
                        " provided is not valid.\nYou can try to use another password"
                        " change protocol such as smbpasswd, server error may be more"
                        " explicit."
                    )

        # We can't modify the object on the fly so let's do it on the class :D
        msldap.commons.exceptions.LDAPModifyException.__str__ = lambda self: error_str
        raise e

    LOG.info("[+] Password changed successfully!")
    return True


def restore(conn, target: str, newName: str = None, newParent: str = None):
    """
    Restore a deleted object

    :param target: sAMAccountName (or name for GPO) or SID of the target (shouldn't be sAMAccountName if there is a duplicate)
    :param newName: new name for the restored object (update also sAMAccountName, UPN, SPN...), if not provided will use the last known RDN
    :param newParent: new parent for the restored object, if not provided will use the last known parent
    """
    if target.lower().startswith("s-1-"):
        ldap_filter = f"(objectSid={target})"
    elif target.startswith("{"):
        ldap_filter = f"(name={target})"
    else:
        ldap_filter = f"(sAMAccountName={target})"
    ldap_filter = f"(&{ldap_filter}(isDeleted=TRUE))"
    entry = next(conn.ldap.bloodysearch(
        "CN=Deleted Objects,"+conn.ldap.domainNC, ldap_filter, search_scope=Scope.SUBTREE, attr=["msDS-LastKnownRDN","lastKnownParent", "sAMAccountName", "servicePrincipalName", "userPrincipalName", "name", "dNSHostName", "displayName"], controls=[("1.2.840.113556.1.4.417", True, None)]
    ))# LDAP_SERVER_SHOW_DELETED_OID
    
    new_dn = f"CN={newName if newName else entry.get('msDS-LastKnownRDN',entry['name'])},{newParent if newParent else entry['lastKnownParent']}"
    attributes = {"distinguishedName": [(Change.REPLACE.value, new_dn)],"isDeleted": [(Change.DELETE.value, [])]}
    if newName:
        attributes["name"] = [(Change.REPLACE.value, newName)]
        attributes["displayName"] = [(Change.REPLACE.value, entry["displayName"].replace(entry["name"], newName))]
        if entry.get("sAMAccountName"):
            attributes["sAMAccountName"] = [(Change.REPLACE.value, newName+'$' if entry["sAMAccountName"][-1] == "$" else newName)]
        if entry.get("servicePrincipalName"):
            attributes["servicePrincipalName"] = [(Change.REPLACE.value, [v.replace(entry["name"],newName) for v in entry["servicePrincipalName"]])]
        if entry.get("userPrincipalName"):
            attributes["userPrincipalName"] = [(Change.REPLACE.value, newName + '@' + entry["userPrincipalName"].split('@')[-1])]
        if entry.get("dNSHostName"):
            attributes["dNSHostName"] = [(Change.REPLACE.value, newName + '.' + entry["dNSHostName"].split('.',1)[-1])]

    try:
        conn.ldap.bloodymodify(
            entry["distinguishedName"], attributes, controls=[("1.2.840.113556.1.4.2064", True, None)]
        )
    except msldap.commons.exceptions.LDAPModifyException as e:
        if "userPrincipalName" in str(e.diagnostic_message) and e.resultcode == 19: # 19 is constraintViolation
            LOG.error(
                "[!] Operation failed, the userPrincipalName is probably already used by another non-deleted object, you have the change the other user UPN first (changing UPN of a deleted object is not allowed)"
            )
            return
        raise e

    LOG.info(f"[+] {target} has been restored successfully under {new_dn}")
