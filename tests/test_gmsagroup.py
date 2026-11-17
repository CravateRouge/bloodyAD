import unittest
from unittest.mock import AsyncMock, MagicMock
from bloodyAD.cli_modules import remove
from bloodyAD.formatters import accesscontrol, ldaptypes
from bloodyAD import utils
from bloodyAD.network.ldap import Change
from bloodyAD.exceptions import BloodyError
import winacl.dtyp.sid as sid


class GmsaGroupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.member1_sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
        self.member2_sid = "S-1-5-21-1111111111-2222222222-3333333333-1002"
        self.access_mask = (
            accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_READ_PROP"]
            | accesscontrol.ACCESS_FLAGS["ADS_RIGHT_DS_CONTROL_ACCESS"]
        )

    def test_delRight_removes_gmsa_ace(self):
        """Test that delRight removes the 0x110 gMSA access ACE from an SD"""
        sd = accesscontrol.createEmptySD()
        ace1 = accesscontrol.createACE(
            sid.SID.from_string(self.member1_sid).to_bytes(),
            None,
            self.access_mask,
        )
        sd["Dacl"].aces.append(ace1)

        # Unpack as getSD does from LDAP
        packed = sd.getData()
        unpacked = ldaptypes.SR_SECURITY_DESCRIPTOR(data=packed)
        self.assertEqual(len(unpacked["Dacl"].aces), 1)

        # Remove the right
        removed = utils.delRight(unpacked, self.member1_sid, self.access_mask)
        self.assertTrue(removed)
        self.assertEqual(len(unpacked["Dacl"].aces), 0)

    def test_delRight_preserves_other_members(self):
        """Test that removing one member leaves other members' ACEs intact"""
        sd = accesscontrol.createEmptySD()
        ace1 = accesscontrol.createACE(
            sid.SID.from_string(self.member1_sid).to_bytes(),
            None,
            self.access_mask,
        )
        ace2 = accesscontrol.createACE(
            sid.SID.from_string(self.member2_sid).to_bytes(),
            None,
            self.access_mask,
        )
        sd["Dacl"].aces.extend([ace1, ace2])

        # Unpack as getSD does from LDAP
        packed = sd.getData()
        unpacked = ldaptypes.SR_SECURITY_DESCRIPTOR(data=packed)
        self.assertEqual(len(unpacked["Dacl"].aces), 2)

        # Remove only member 1
        removed = utils.delRight(unpacked, self.member1_sid, self.access_mask)
        self.assertTrue(removed)
        self.assertEqual(len(unpacked["Dacl"].aces), 1)
        remaining_sid = (
            unpacked["Dacl"].aces[0]["Ace"]["Sid"].formatCanonical()
        )
        self.assertEqual(remaining_sid, self.member2_sid)

    async def test_remove_gmsaGroup_single_member_deletes_attribute(self):
        """Test that removing the sole member issues Change.DELETE"""
        sd = accesscontrol.createEmptySD()
        ace = accesscontrol.createACE(
            sid.SID.from_string(self.member1_sid).to_bytes(),
            None,
            self.access_mask,
        )
        sd["Dacl"].aces.append(ace)
        packed = sd.getData()
        unpacked = ldaptypes.SR_SECURITY_DESCRIPTOR(data=packed)

        mock_ldap = AsyncMock()
        mock_conn = MagicMock()
        mock_conn.getLdap = AsyncMock(return_value=mock_ldap)

        # Mock bloodysearch generator
        async def mock_search(target, attr):
            yield {"objectSid": self.member1_sid}

        mock_ldap.bloodysearch = mock_search

        # Mock utils.getSD to return our unpacked SD
        async def mock_get_sd(conn, object_id, attr, control_flag):
            return unpacked, [packed]

        original_get_sd = utils.getSD
        utils.getSD = mock_get_sd
        try:
            await remove.gmsaGroup(mock_conn, "testgmsa$", "testuser")
        finally:
            utils.getSD = original_get_sd

        mock_ldap.bloodymodify.assert_called_once_with(
            "testgmsa$",
            {"msDS-GroupMSAMembership": [(Change.DELETE.value, [])]},
        )

    async def test_remove_gmsaGroup_multiple_members_replaces_attribute(self):
        """Test that removing one member when others exist issues Change.REPLACE"""
        sd = accesscontrol.createEmptySD()
        ace1 = accesscontrol.createACE(
            sid.SID.from_string(self.member1_sid).to_bytes(),
            None,
            self.access_mask,
        )
        ace2 = accesscontrol.createACE(
            sid.SID.from_string(self.member2_sid).to_bytes(),
            None,
            self.access_mask,
        )
        sd["Dacl"].aces.extend([ace1, ace2])
        packed = sd.getData()
        unpacked = ldaptypes.SR_SECURITY_DESCRIPTOR(data=packed)

        mock_ldap = AsyncMock()
        mock_conn = MagicMock()
        mock_conn.getLdap = AsyncMock(return_value=mock_ldap)

        async def mock_search(target, attr):
            yield {"objectSid": self.member1_sid}

        mock_ldap.bloodysearch = mock_search

        async def mock_get_sd(conn, object_id, attr, control_flag):
            return unpacked, [packed]

        original_get_sd = utils.getSD
        utils.getSD = mock_get_sd
        try:
            await remove.gmsaGroup(mock_conn, "testgmsa$", "testuser")
        finally:
            utils.getSD = original_get_sd

        mock_ldap.bloodymodify.assert_called_once()
        args = mock_ldap.bloodymodify.call_args[0]
        self.assertEqual(args[0], "testgmsa$")
        change_op, new_data = args[1]["msDS-GroupMSAMembership"][0]
        self.assertEqual(change_op, Change.REPLACE.value)
        self.assertTrue(len(new_data) > 0)

    async def test_remove_gmsaGroup_member_not_found_raises_error(self):
        """Test that resolving a non-existent member raises BloodyError"""
        mock_ldap = AsyncMock()
        mock_conn = MagicMock()
        mock_conn.getLdap = AsyncMock(return_value=mock_ldap)

        async def mock_empty_search(target, attr):
            if False:
                yield {}

        mock_ldap.bloodysearch = mock_empty_search

        sd = accesscontrol.createEmptySD()
        packed = sd.getData()
        unpacked = ldaptypes.SR_SECURITY_DESCRIPTOR(data=packed)

        async def mock_get_sd(conn, object_id, attr, control_flag):
            return unpacked, [packed]

        original_get_sd = utils.getSD
        utils.getSD = mock_get_sd
        try:
            with self.assertRaises(BloodyError) as ctx:
                await remove.gmsaGroup(mock_conn, "testgmsa$", "nonexistentuser")
            self.assertIn("nonexistentuser", str(ctx.exception))
        finally:
            utils.getSD = original_get_sd


if __name__ == "__main__":
    unittest.main()
