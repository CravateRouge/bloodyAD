import ldap3
from bloodyAD import utils
from bloodyAD.utils import LOG

# Full info on what you can do:
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/change-windows-active-directory-user-password
def password(conn, target: str, newpass: str, oldpass: str = None):
    """
    Change password of a user/computer

    :param target: sAMAccountName, DN, GUID or SID of the target
    :param newpass: new password for the target
    :param oldpass: old password of the target, mandatory if you don't have "change password" permission on the target
    """
    ldap_conn = conn.getLdapConnection()
    target_dn = utils.resolvDN(ldap_conn, target)

    encoded_new_password = ('"%s"' % newpass).encode('utf-16-le')
    if oldpass is not None:
        encoded_old_password = ('"%s"' % oldpass).encode('utf-16-le')
        op_list = [
            (ldap3.MODIFY_DELETE, [encoded_old_password]),
            (ldap3.MODIFY_ADD, [encoded_new_password])
        ]
    else:
        op_list = [(ldap3.MODIFY_REPLACE, [encoded_new_password])]
    
    try:
        ldap_conn.modify(target_dn, {'unicodePwd': op_list})
    except ldap3.core.exceptions.LDAPConstraintViolationResult as e:
        error_str = "If it's a user, double check new password fits password policy (don't forget password history and password change frequency!)"
        if oldpass is not None:
            error_str += ", also ensure old password is valid"
        ldap3.core.exceptions.LDAPConstraintViolationResult.__str__ = lambda self: error_str

        raise e

    LOG.info("[+] Password changed successfully!")
    return True