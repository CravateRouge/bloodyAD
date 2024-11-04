from bloodyAD import utils
from bloodyAD.exceptions import LOG
from bloodyAD.formatters import accesscontrol
from bloodyAD.network.ldap import Change
import msldap
from datetime import datetime, timezone, timedelta
import unicodedata


def object(conn, target: str, attribute: str, v: list = [], raw: bool = False):
    """
    Add/Replace/Delete target's attribute

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param attribute: name of the attribute
    :param v: add value if attribute doesn't exist, replace value if attribute exists, delete if no value given, can be called multiple times if multiple values to set (e.g -v HOST/janettePC -v HOST/janettePC.bloody.local)
    :param raw: if set, will try to send the values provided as is, without any encoding
    """
    # Converting raw str into raw binary
    if raw:
        tmp_v = []
        for vstr in v:
            tmp_v.add(vstr.encode())
        v = tmp_v

    conn.ldap.bloodymodify(
        target, {attribute: [(Change.REPLACE.value, v)]}, encode=(not raw)
    )
    LOG.info(f"[+] {target}'s {attribute} has been updated")


def owner(conn, target: str, owner: str):
    """
    Changes target ownership with provided owner (WriteOwner permission required)

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param owner: sAMAccountName, DN, GUID or SID of the new owner
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

    :param target: sAMAccountName, DN, GUID or SID of the target
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
                print(pwdPolicy)
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
