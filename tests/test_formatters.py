import unittest
from bloodyAD.formatters import formatters


class FormatterTests(unittest.TestCase):
    def test_getFormatters(self):
        """Test that getFormatters returns expected attribute mappings"""
        formatter_map = formatters.getFormatters()
        
        # Check that we have formatters for key attributes
        self.assertIn("nTSecurityDescriptor", formatter_map)
        self.assertIn("userAccountControl", formatter_map)
        self.assertIn("trustDirection", formatter_map)
        self.assertIn("dnsRecord", formatter_map)
        self.assertIn("msDS-ManagedPassword", formatter_map)
        
        # Verify that formatters are callable
        self.assertTrue(callable(formatter_map["nTSecurityDescriptor"]))
        self.assertTrue(callable(formatter_map["userAccountControl"]))

    def test_applyFormatters_no_matching_attributes(self):
        """Test applyFormatters with attributes that don't need formatting"""
        attributes = {
            "distinguishedName": "CN=Test,DC=example,DC=com",
            "cn": "Test",
            "objectClass": ["top", "person"]
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # Attributes without formatters should remain unchanged
        self.assertEqual(result, attributes)

    def test_applyFormatters_with_userAccountControl_single_value(self):
        """Test applyFormatters with userAccountControl attribute as single-item list"""
        attributes = {
            "cn": "Test",
            "userAccountControl": [b"512"]  # NORMAL_ACCOUNT in list
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # cn should remain unchanged
        self.assertEqual(result["cn"], "Test")
        # userAccountControl should be formatted as a list
        self.assertIsInstance(result["userAccountControl"], list)
        self.assertIn("NORMAL_ACCOUNT", result["userAccountControl"])

    def test_applyFormatters_with_userAccountControl_bytes(self):
        """Test applyFormatters with userAccountControl as direct bytes"""
        attributes = {
            "userAccountControl": b"512"  # Direct bytes value
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # Should be formatted as a list
        self.assertIsInstance(result["userAccountControl"], list)
        self.assertIn("NORMAL_ACCOUNT", result["userAccountControl"])

    def test_applyFormatters_with_list_values(self):
        """Test applyFormatters with multiple list values"""
        attributes = {
            "userAccountControl": [b"512", b"544"]  # Multiple values
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # Should format each value in the list
        self.assertIsInstance(result["userAccountControl"], list)
        self.assertEqual(len(result["userAccountControl"]), 2)
        
    def test_applyFormatters_with_trustDirection_single_item_list(self):
        """Test applyFormatters with trustDirection attribute as single-item list"""
        attributes = {
            "trustDirection": [b"3"]  # BIDIRECTIONAL in list
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # trustDirection should be formatted (single value from list)
        self.assertEqual(result["trustDirection"], "BIDIRECTIONAL")

    def test_applyFormatters_with_trustDirection_bytes(self):
        """Test applyFormatters with trustDirection as direct bytes"""
        attributes = {
            "trustDirection": b"3"  # Direct bytes value
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # trustDirection should be formatted
        self.assertEqual(result["trustDirection"], "BIDIRECTIONAL")

    def test_applyFormatters_empty_formatters(self):
        """Test applyFormatters with empty formatters dict (raw mode)"""
        attributes = {
            "cn": "Test",
            "userAccountControl": [b"512"]
        }
        
        result = formatters.applyFormatters(attributes, {})
        
        # All attributes should remain unchanged
        self.assertEqual(result, attributes)

    def test_enableEncoding(self):
        """Test that enableEncoding modifies encoding dictionary"""
        from badldap.protocol.typeconversion import MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC
        
        # Call enableEncoding
        formatters.enableEncoding()
        
        # Verify that msDS-AllowedToActOnBehalfOfOtherIdentity is in encoding dict
        self.assertIn("msDS-AllowedToActOnBehalfOfOtherIdentity", MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC)


if __name__ == '__main__':
    unittest.main()
