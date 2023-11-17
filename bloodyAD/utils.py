from bloodyAD.formatters import (
    ldaptypes,
    accesscontrol,
    adschema,
)
import logging, json, sys, types, base64
import ldap3
from winacl import dtyp
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from pyasn1.type import namedtype, univ


LOG = logging.getLogger("bloodyAD")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
LOG.addHandler(handler)


def addRight(
    sd,
    user_sid,
    access_mask=accesscontrol.ACCESS_FLAGS["FULL_CONTROL"],
    object_type=None,
):
    user_sid = dtyp.sid.SID.from_string(user_sid)
    user_aces = [
        ace
        for ace in sd["Dacl"].aces
        if ace["Ace"]["Sid"].getData() == user_sid.to_bytes()
    ]
    new_ace = accesscontrol.createACE(user_sid.to_bytes(), object_type, access_mask)
    if object_type:
        access_denied_type = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
    else:
        access_denied_type = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
    hasPriv = False

    for ace in user_aces:
        new_mask = new_ace["Ace"]["Mask"]
        mask = ace["Ace"]["Mask"]

        # Removes Access-Denied ACEs interfering
        if ace["AceType"] == access_denied_type and new_mask.hasPriv(mask["Mask"]):
            sd["Dacl"].aces.remove(ace)
            LOG.debug("[-] An interfering Access-Denied ACE has been removed:")
            LOG.info(json.dumps(accesscontrol.decodeAce(ace)))
        # Adds ACE if not already added
        elif mask.hasPriv(new_mask["Mask"]):
            hasPriv = True
            break

    if hasPriv:
        LOG.debug("[!] This right already exists")
    else:
        sd["Dacl"].aces.append(new_ace)

    isAdded = not hasPriv
    return isAdded


def delRight(
    sd,
    user_sid,
    access_mask=accesscontrol.ACCESS_FLAGS["FULL_CONTROL"],
    object_type=None,
):
    isRemoved = False
    user_sid = dtyp.sid.SID.from_string(user_sid)
    user_aces = [
        ace
        for ace in sd["Dacl"].aces
        if ace["Ace"]["Sid"].getData() == user_sid.to_bytes()
    ]
    if object_type:
        access_allowed_type = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    else:
        access_allowed_type = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE

    for ace in user_aces:
        mask = ace["Ace"]["Mask"]
        if ace["AceType"] == access_allowed_type and mask.hasPriv(access_mask):
            mask.removePriv(access_mask)
            LOG.debug("[-] Privilege Removed")
            if mask["Mask"] == 0:
                sd["Dacl"].aces.remove(ace)
            isRemoved = True

    if not isRemoved:
        LOG.debug("[!] No right to remove")
    return isRemoved


def getSD(
    conn,
    object_id,
    ldap_attribute="nTSecurityDescriptor",
    control_flag=accesscontrol.DACL_SECURITY_INFORMATION,
):
    sd_data = next(
        conn.ldap.bloodysearch(
            object_id, attr=ldap_attribute, control_flag=control_flag, raw=True
        )
    )[ldap_attribute]
    if len(sd_data) < 1:
        LOG.warning(
            "[!] No security descriptor has been returned, a new one will be created"
        )
        sd = accesscontrol.createEmptySD()
    else:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

    LOG.debug(
        "[*] Old Security Descriptor: "
        + "\t".join([SECURITY_DESCRIPTOR.from_bytes(sd).to_sddl() for sd in sd_data])
    )
    return sd, sd_data


# First elt in grouping order is the first grouping criterium
def groupBy(rows, grouping_order):
    try:
        grouping_key = grouping_order.pop()
        merged = groupBy(rows, grouping_order)
    except IndexError:  # We exhausted all grouping criteriums
        return rows

    new_merge = []
    for row in merged:
        isMergeable = False
        for new_row in new_merge:
            isMergeable = True
            for k in row:
                if k == grouping_key:
                    continue
                try:
                    if row[k] != new_row[k]:
                        isMergeable = False
                        break
                except (
                    KeyError
                ):  # If one of the rows doesn't have the non grouping property, it can't be merged
                    continue
            if isMergeable:
                new_row[grouping_key] |= row[grouping_key]
                break
        if not isMergeable:
            new_merge.append(row)
    return new_merge


ACCESS_RIGHTS = {
    "CREATE_CHILD": (0x1,),
    "DELETE_CHILD": (0x2,),
    "LIST_CHILD": (0x4,),  # LIST_CONTENTS
    "WRITE_VALIDATED": (0x8,),  # WRITE_PROPERTY_EXTENDED
    "READ_PROP": (0x10,),
    "WRITE_PROP": (0x20,),  # Does it contains WRITE VALIDATED?
    "DELETE_TREE": (0x40,),
    "LIST_OBJECT": (0x80,),
    "CONTROL_ACCESS": (0x100,),
    "DELETE": (0x10000,),
    "READ_SD": (0x20000,),
    "WRITE_DACL": (0x40000,),
    "WRITE_OWNER": (0x80000,),
    "ACCESS_SYSTEM_SECURITY": (0x1000000,),
    "SYNCHRONIZE": (0x100000,),
}
ACCESS_RIGHTS["GENERIC_EXECUTE"] = (
    0x20000000,
    ACCESS_RIGHTS["READ_SD"][0] | ACCESS_RIGHTS["LIST_CHILD"][0],
)
ACCESS_RIGHTS["GENERIC_WRITE"] = (
    0x40000000,
    ACCESS_RIGHTS["READ_SD"][0]
    | ACCESS_RIGHTS["WRITE_PROP"][0]
    | ACCESS_RIGHTS["WRITE_VALIDATED"][0],
)
ACCESS_RIGHTS["GENERIC_READ"] = (
    0x80000000,
    ACCESS_RIGHTS["READ_SD"][0]
    | ACCESS_RIGHTS["READ_PROP"][0]
    | ACCESS_RIGHTS["LIST_CHILD"][0]
    | ACCESS_RIGHTS["LIST_OBJECT"][0],
)
ACCESS_RIGHTS["GENERIC_ALL"] = (
    0x10000000,
    ACCESS_RIGHTS["GENERIC_EXECUTE"][0]
    | ACCESS_RIGHTS["GENERIC_WRITE"][0]
    | ACCESS_RIGHTS["GENERIC_READ"][0]
    | ACCESS_RIGHTS["DELETE"][0]
    | ACCESS_RIGHTS["DELETE_TREE"][0]
    | ACCESS_RIGHTS["CONTROL_ACCESS"][0]
    | ACCESS_RIGHTS["CREATE_CHILD"][0]
    | ACCESS_RIGHTS["DELETE_CHILD"][0]
    | ACCESS_RIGHTS["WRITE_DACL"][0]
    | ACCESS_RIGHTS["WRITE_OWNER"][0],
    ACCESS_RIGHTS["READ_SD"][0]
    | ACCESS_RIGHTS["READ_PROP"][0]
    | ACCESS_RIGHTS["LIST_CHILD"][0]
    | ACCESS_RIGHTS["LIST_OBJECT"][0]
    | ACCESS_RIGHTS["WRITE_PROP"][0]
    | ACCESS_RIGHTS["WRITE_VALIDATED"][0]
    | ACCESS_RIGHTS["DELETE"][0]
    | ACCESS_RIGHTS["DELETE_TREE"][0]
    | ACCESS_RIGHTS["CONTROL_ACCESS"][0]
    | ACCESS_RIGHTS["CREATE_CHILD"][0]
    | ACCESS_RIGHTS["DELETE_CHILD"][0]
    | ACCESS_RIGHTS["WRITE_DACL"][0]
    | ACCESS_RIGHTS["WRITE_OWNER"][0],
)
# Reverse is sorted for mask operations
REVERSE_ACCESS_RIGHTS = dict(
    sorted(
        [
            (mask, flag)
            for flag, masktuple in ACCESS_RIGHTS.items()
            for mask in masktuple
        ],
        reverse=True,
    )
)


class Right:
    def __init__(self, mask):
        self.mask = mask

    def __str__(self):
        flag_list = []
        tmp_mask = self.mask
        for key_mask in REVERSE_ACCESS_RIGHTS:
            if (
                key_mask & ~tmp_mask
            ) > 0:  # Means key_mask is including bits not in tmp_mask
                continue
            remainder = (
                tmp_mask & ~key_mask
            )  # We keep a remainder of tmp_mask with complement of key_mask if tmp_mask is bigger than key_mask
            flag_list.append(REVERSE_ACCESS_RIGHTS[key_mask])
            tmp_mask = remainder
            if remainder == 0:
                break
        if tmp_mask != 0:  # If there is unknown mask
            flag_list.append(str(tmp_mask))
        return "|".join(flag_list)


class Control:
    def __init__(self, control_enum):
        self.control_enum = control_enum

    def __str__(self):
        flag_str = repr(self.control_enum).split(".")[1].split(":")[0]
        flag_str = flag_str.replace("SE_", "")
        return flag_str


class AceType:
    def __init__(self, acetype_enum):
        self.acetype_enum = acetype_enum

    def __eq__(self, o):
        if not isinstance(o, AceType):
            return NotImplemented
        return self.acetype_enum == o.acetype_enum

    def __str__(self):
        flag_str = repr(self.acetype_enum).split(".")[1].split(":")[0]
        flag_str = flag_str.replace("ACCESS_", "")
        flag_str = flag_str.replace("SYSTEM_", "")
        flag_str = flag_str.replace("_ACE_TYPE", "")
        return f"== {flag_str} =="


class AceFlag:
    def __init__(self, aceflag_enum):
        self.aceflag_enum = aceflag_enum

    def __str__(self):
        flag_str = repr(self.aceflag_enum).split(".")[1].split(":")[0]
        flag_str = flag_str.replace("_ACE_FLAG", "")
        flag_str = flag_str.replace("_ACE", "")
        return flag_str


class LazyAdSchema:
    guids = set()
    sids = set()
    guid_dict = {
        **adschema.OBJECT_TYPES,
        "Self": "Self",
    }  # Special object to design rule applies to self
    sid_dict = dtyp.sid.well_known_sids_sid_name_map
    isResolved = False

    def _resolveAll(self):
        if self.isResolved:
            return

        # WARNING: only 512 filters max per request
        filters = []
        buffer_filter = ""
        filter_nb = 0
        for sid in self.sids:
            if filter_nb > 511:
                filters.append(buffer_filter)
                buffer_filter = ""
                filter_nb = 0
            buffer_filter += f"(objectSid={sid})"
            filter_nb += 1
        for guid in self.guids:
            if filter_nb > 511:
                filters.append(buffer_filter)
                buffer_filter = ""
                filter_nb = 0
            guid_bin_str = "\\" + "\\".join([
                "{:02x}".format(b)
                for b in dtyp.guid.GUID().from_string(guid).to_bytes()
            ])
            buffer_filter += f"(rightsGuid={str(guid)})(schemaIDGUID={guid_bin_str})"
            filter_nb += 2
        filters.append(buffer_filter)

        # Search in all non application partitions
        # TODO: search in GC and add domain linked to it as DOMAIN\sAMAccountName, maybe try trusts in the future?
        class SearchOptionsRequest(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("Flags", univ.Integer())
            )

        scontrols = SearchOptionsRequest()
        SERVER_SEARCH_FLAG_PHANTOM_ROOT = 2
        scontrols.setComponentByName("Flags", SERVER_SEARCH_FLAG_PHANTOM_ROOT)
        LDAP_SERVER_SEARCH_OPTIONS_OID = "1.2.840.113556.1.4.1340"
        controls = [
            ldap3.protocol.controls.build_control(
                LDAP_SERVER_SEARCH_OPTIONS_OID, False, scontrols
            )
        ]
        for ldap_filter in filters:
            entries = self.conn.ldap.bloodysearch(
                "",
                ldap_filter=f"(|{ldap_filter})",
                attr=[
                    "name",
                    "sAMAccountName",
                    "objectSid",
                    "rightsGuid",
                    "schemaIDGUID",
                ],
                search_scope=ldap3.SUBTREE,
                controls=controls,
            )
            for entry in entries:
                if entry["objectSid"]:
                    self.sid_dict[entry["objectSid"]] = (
                        entry["sAMAccountName"]
                        if entry["sAMAccountName"]
                        else entry["name"]
                    )
                else:
                    if entry["rightsGuid"]:
                        key = entry["rightsGuid"]
                    elif entry["schemaIDGUID"]:
                        key = entry["schemaIDGUID"][
                            1:-1
                        ]  # Removes brackets for GUID formatted with ldap3 format_uuid_le
                    else:
                        LOG.warning(f"[!] No guid/sid returned for {entry}")
                        continue
                    self.guid_dict[key] = entry["name"]
        # Cleanup resolved ids from queues
        self.isResolved = True
        self.guids = set()
        self.sids = set()

    def addguid(self, guid):
        # Should not add in set to resolve after if it is already resolved
        if guid not in self.guid_dict:
            self.guids.add(guid)

    def addsid(self, sid):
        if sid not in self.sid_dict:
            self.sids.add(sid)

    def getguid(self, guid):
        try:
            return self.guid_dict[guid]
        except KeyError:
            if not self.isResolved:
                self._resolveAll()
                return self.getguid(guid)
            else:
                return guid

    def getsid(self, sid):
        try:
            return self.sid_dict[sid]
        except KeyError:
            if not self.isResolved:
                self._resolveAll()
                return self.getsid(sid)
            else:
                return sid


global_lazy_adschema = LazyAdSchema()


class LazyGuid:
    def __init__(self, guid):
        self.guid = guid
        global_lazy_adschema.addguid(guid)

    def __str__(self):
        return global_lazy_adschema.getguid(self.guid)


class LazySid:
    def __init__(self, sid):
        self.sid = sid
        global_lazy_adschema.addsid(sid)

    def __str__(self):
        return global_lazy_adschema.getsid(self.sid)


def aceFactory(k, a):
    if k == "Trustee":
        return LazySid(a)
    elif k == "Right":
        return Right(a)
    elif k in ("ObjectType", "InheritedObjectType"):
        return LazyGuid(a)
    elif k == "Flags":
        return AceFlag(a)
    else:
        return a


def renderSD(sddl, conn):
    global_lazy_adschema.conn = conn
    sd = SECURITY_DESCRIPTOR.from_sddl(sddl)
    # We don't print Revision because it's always 1,
    # Group isn't used in ADDS
    renderedSD = {"Owner": LazySid(str(sd.Owner)), "Control": Control(sd.Control)}
    rendered_aces = []
    allAces = []
    if sd.Dacl:
        allAces += sd.Dacl.aces
    if sd.Sacl:
        allAces += sd.Sacl.aces
    for ace in allAces:
        rendered_ace = {
            "Type": AceType(ace.AceType),
            "Trustee": set([str(ace.Sid)]),
            "Right": ace.Mask,
            "ObjectType": set(),
            "InheritedObjectType": set(),
            "Flags": ace.AceFlags,
        }

        if hasattr(ace, "ObjectType") and ace.ObjectType:
            object_guid_str = str(ace.ObjectType)
        else:
            object_guid_str = "Self"
        rendered_ace["ObjectType"].add(object_guid_str)
        if hasattr(ace, "InheritedObjectType") and ace.InheritedObjectType:
            rendered_ace["InheritedObjectType"].add(str(ace.InheritedObjectType))

        rendered_aces.append(rendered_ace)

    grouped_aces = groupBy(
        rendered_aces,
        ["ObjectType", "Trustee", "Flags", "InheritedObjectType", "Right"],
    )
    typed_aces = []
    for ace in grouped_aces:
        typed_ace = {}
        for k, v in ace.items():
            if not v:
                continue
            try:
                typed_ace[k] = []
                for a in v:  # If it's a set of guids/sids
                    typed_ace[k].append(aceFactory(k, a))
            except TypeError:  # If it's a mask
                typed_ace[k] = aceFactory(k, v)

        typed_aces.append(typed_ace)

    renderedSD["ACL"] = typed_aces

    return renderedSD


def renderSearchResult(entries):
    """
    Takes entries of type Iterator({dn: <list/generator with one depth or primitive type or raw bytes>},{...}...)
    Returns entries as is but with base64 instead of raw bytes if not decodable in utf-8
    Sorts entry alphabetically too
    """
    decoded_entry = {}
    for entry in entries:
        entry = {
            **{"distinguishedName": entry["distinguishedName"]},
            **{k: v for k, v in sorted(entry.items()) if k != "distinguishedName"},
        }
        for attr_name, attr_members in entry.items():
            if type(attr_members) in [list, types.GeneratorType]:
                decoded_entry[attr_name] = []
                for member in attr_members:
                    if type(member) == bytes:
                        try:
                            decoded = member.decode()
                        except UnicodeDecodeError:
                            decoded = base64.b64encode(member).decode()
                    else:
                        decoded = member
                    decoded_entry[attr_name].append(decoded)
            else:
                if type(attr_members) == bytes:
                    try:
                        decoded = attr_members.decode()
                    except UnicodeDecodeError:
                        decoded = base64.b64encode(attr_members).decode()
                else:
                    decoded = attr_members
                decoded_entry[attr_name] = decoded
        yield decoded_entry
        decoded_entry = {}
