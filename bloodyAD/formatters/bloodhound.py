from badldap.ldap_objects import (
    MSADUser, MSADMachine, MSADGroup, MSADOU, MSADGPO, 
    MSADContainer, MSADDMSAUser, MSADGMSAUser, MSADDomainTrust
)
from badldap.wintypes.asn1.sdflagsrequest import SDFlagsRequestValue
from bloodyAD.formatters import accesscontrol
from badldap.external.bloodhoundpy.resolver import resolve_aces, WELLKNOWN_SIDS
from badldap.external.bloodhoundpy.acls import parse_binary_acl
from badldap.bloodhound import MSLDAPDump2Bloodhound
import zipfile
from bloodyAD.network.ldap import showRecoverable
from bloodyAD.exceptions import LOG
from bloodyAD.utils import global_lazy_adschema

def create_msldapentry(entry, otype):
    """
    Create a badldap ldapentry object from a dictionary entry based on resolved type.
    """
    
    if otype == 'user':
        object_class = entry["attributes"].get('objectClass', [])
        if 'msDS-GroupManagedServiceAccount' in object_class:
            return MSADGMSAUser.from_ldap(entry)
        elif 'msDS-ManagedServiceAccount' in object_class:
            return MSADDMSAUser.from_ldap(entry)
        else:
            return MSADUser.from_ldap(entry)
    elif otype == 'computer':
        return MSADMachine.from_ldap(entry)
    elif otype == 'group':
        return MSADGroup.from_ldap(entry)
    elif otype == 'gpo':
        return MSADGPO.from_ldap(entry)
    elif otype == 'ou':
        return MSADOU.from_ldap(entry)
    elif otype == 'domain':
        return MSADDomainTrust.from_ldap(entry)
    else:
        # container, domain, base, trustaccount, or unknown
        return MSADContainer.from_ldap(entry)


async def granular_bh(conn, searchbase, ldap_filter, output_path=None):
    """
    Generate BloodHound-compatible JSON for queried objects.
    """
    ldap = await conn.getLdap()
    msbh = MSLDAPDump2Bloodhound(ldap.co_url)
    additional_schema = {
        'ms-mcs-admpwd': '79775c0c-d2e0-4b5f-b8e5-0e8e6a0c0e0e',  # LAPS password attribute
        'ms-laps-encryptedpassword': 'c835d1d5-f9fb-4c5b-8b8f-8b6f9b6f9b6f',  # LAPS encrypted password
        'ms-ds-key-credential-link': '5b47d60f-6090-40b2-9f37-2a4de88f3063',  # Key Credential Link
        'service-principal-name': 'f3a64788-5306-11d1-a9c5-0000f80367c1',  # SPN attribute
        'user-principal-name': '28630ebf-41d5-11d1-a9c1-0000f80367c1',  # UPN attribute
    }
    msbh.schema.update(additional_schema)
    msbh.domainname = ldap.domainname
    bh_data = {}
    filectr_dict = {}
    group_members = {}
    adinfo, err = await ldap.get_ad_info()
    if err:
        raise err
    control_flag=(
            accesscontrol.OWNER_SECURITY_INFORMATION
            + accesscontrol.GROUP_SECURITY_INFORMATION
            + accesscontrol.DACL_SECURITY_INFORMATION
        )
    req_flags = SDFlagsRequestValue({"Flags": control_flag})
    # First one for recycled and second one for nt security descriptor
    controls = showRecoverable() +[("1.2.840.113556.1.4.801", True, req_flags.dump())]
    with zipfile.ZipFile(msbh.zipfilepath, 'w', zipfile.ZIP_DEFLATED) as msbh.zipfile:
        async for entry, err in ldap.pagedsearch(ldap_filter, attributes=['*'], tree=searchbase, controls=controls):
            if err:
                raise err
            entry_attr = entry['attributes']
            # Deal with known foreign principals
            gname = ""
            if entry_attr.get('name') in WELLKNOWN_SIDS:
                    bh_entry = {}
                    gname, sidtype = WELLKNOWN_SIDS[entry_attr['name']]
                    obj_type = sidtype.lower()
                    # bh_entry['type'] = sidtype.capitalize()
                    # bh_entry['principal'] = '%s@%s' % (gname.upper(), msbh.domainname.upper())
                    # bh_entry['ObjectIdentifier'] = '%s-%s' % (msbh.domainname.upper(), entry_attr['objectSid'].upper())
            else:
                resolved = msbh.resolve_entry(entry_attr)
                obj_type = resolved['type'].lower()
                if obj_type == 'trustaccount':
                    obj_type = 'user'  # We will consider Trust accounts are users in BH for now
            msldap_entry = create_msldapentry(entry, obj_type)                
            try:
                bh_entry = msldap_entry.to_bh(ldap.domainname, adinfo.objectSid)
            except TypeError:
                try:
                    bh_entry = msldap_entry.to_bh(ldap.domainname)
                except TypeError:
                    bh_entry = msldap_entry.to_bh()
            if gname:
                bh_entry['Properties']['name'] = gname
            elif entry_attr.get('isDeleted'):
                bh_entry['Properties']['name'] = '%s@%s' % (entry_attr['name'].replace('\n',' ').upper(), ldap.domainname.upper())
            # Parse the ACL
            dn_entry, bh_entry, relations = parse_binary_acl(
                entry_attr['distinguishedName'], 
                bh_entry, 
                obj_type, 
                entry['attributes']['nTSecurityDescriptor'], 
                msbh.schema
            )

            # Add to object cache for group membership resolution
            msbh.add_ocache(dn_entry, bh_entry['ObjectIdentifier'], bh_entry['Properties']['name'], obj_type)

            bh_entry['Aces'] = resolve_aces(relations, ldap.domainname, adinfo.objectSid, msbh.ocache)
            
            json_type = obj_type + 's'
            bh_type_data = bh_data.get(json_type, msbh.get_json_wrapper(json_type))
            bh_type_data['data'].append(bh_entry)
            bh_type_data['meta']['count'] += 1

            # For groups we need post processing to resolve members so we cannot flush now
            if json_type == 'groups':
                group_members[bh_entry['ObjectIdentifier']] = entry_attr.get('member', [])
            elif bh_type_data['meta']['count'] == msbh.MAX_ENTRIES_PER_FILE:
                LOG.info('Max entries per file reached for %s, flushing %d entries to zip' % (json_type, bh_type_data['meta']['count']))
                filectr = filectr_dict.get(json_type, 0)
                await msbh.write_json_to_zip(json_type, bh_type_data, filectr)
                bh_type_data = msbh.get_json_wrapper(json_type)
                filectr_dict[json_type] = filectr + 1
            bh_data[json_type] = bh_type_data

        for bh_type, bh_type_data in bh_data.items():
            if bh_type_data['meta']['count'] > 0:
                # If it's a group we populate members objectId now
                if bh_type == 'groups':
                    await process_members(conn, bh_type_data, group_members, msbh.DNs)
                filectr = filectr_dict.get(bh_type, 0)
                await msbh.write_json_to_zip(bh_type, bh_type_data, filectr)
                LOG.info('Flushing %d %s entries to zip' % (bh_type_data['meta']['count'], bh_type))

    LOG.info('Bloodhound data saved to %s' % msbh.zipfilepath)

async def process_members(conn, bh_type_data, group_members, dn_to_sid):
    """
    For each group entry in bh_type_data, populate its 'Members' property with resolved ObjectIdentifiers.
    Uses dn_to_sid for fast lookup, and LazyAdSchema for unresolved DNs.
    """
    # The dn_to_sid gonna be updated by lazy schema and that's the goal
    global_lazy_adschema.dn_dict = dn_to_sid
    global_lazy_adschema.conn = conn

    # Add all DNs to LazyAdSchema for resolution
    for members_DNs in group_members.values():
        for dn in members_DNs:
            global_lazy_adschema.adddn(dn)

    # For each group entry, populate Members with ObjectIdentifiers
    for entry in bh_type_data['data']:
        group_objid = entry.get('ObjectIdentifier')
        members_DNs = group_members[group_objid]
        members_objids = []
        for dn in members_DNs:
            objid = await global_lazy_adschema.getdn(dn.upper())
            # If no obj id found, skip the member
            if objid:
                if objid.upper() in WELLKNOWN_SIDS:
                    objid = '%s-%s' % (entry['Properties']['domain'], objid.upper())
                members_objids.append({"ObjectIdentifier": objid})
        entry['Members'] = members_objids