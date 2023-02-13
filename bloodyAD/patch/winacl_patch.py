from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR, sddl_acl_control

def to_sddl(self, object_type = None):
    t=''
    if self.Owner is not None:
        t =  'O:' + self.Owner.to_sddl()
    if self.Group is not None:
        t += 'G:' + self.Group.to_sddl()
    if self.Sacl is not None:
        t+= 'S:' + sddl_acl_control(self.Control) + self.Sacl.to_sddl(object_type)
    if self.Dacl is not None:
        t+= 'D:' + sddl_acl_control(self.Control) + self.Dacl.to_sddl(object_type)
    return t

SECURITY_DESCRIPTOR.to_sddl = to_sddl