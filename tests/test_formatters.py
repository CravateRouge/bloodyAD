import unittest
from bloodyAD.formatters import formatters


class FormatterTests(unittest.TestCase):
    def test_getFormatters(self):
        """Test that getFormatters returns expected attribute mappings"""
        formatter_map = formatters.getFormatters()
        
        # Check that we have formatters for key bloodyAD custom attributes
        self.assertIn("nTSecurityDescriptor", formatter_map)
        self.assertIn("userAccountControl", formatter_map)
        self.assertIn("trustDirection", formatter_map)
        self.assertIn("dnsRecord", formatter_map)
        self.assertIn("msDS-ManagedPassword", formatter_map)
        
        # Check that we have badldap default formatters too
        self.assertIn("objectSid", formatter_map)
        self.assertIn("objectGUID", formatter_map)
        self.assertIn("cn", formatter_map)
        
        # Verify that formatters are callable
        self.assertTrue(callable(formatter_map["nTSecurityDescriptor"]))
        self.assertTrue(callable(formatter_map["userAccountControl"]))
        self.assertTrue(callable(formatter_map["objectSid"]))

    def test_applyFormatters_no_matching_attributes(self):
        """Test applyFormatters with attributes that don't need formatting"""
        attributes = {
            "distinguishedName": "CN=Test,DC=example,DC=com",
            "someUnknownAttr": [b"test"],
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # Unknown attributes should remain unchanged
        self.assertEqual(result["distinguishedName"], "CN=Test,DC=example,DC=com")
        self.assertEqual(result["someUnknownAttr"], [b"test"])

    def test_applyFormatters_with_badldap_formatter(self):
        """Test that badldap default formatters are applied"""
        import uuid
        test_guid = uuid.uuid4().bytes
        
        attributes = {
            "objectGUID": [test_guid],
            "cn": [b"TestUser"]
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # objectGUID should be formatted to string
        self.assertIsInstance(result["objectGUID"], str)
        # cn should be formatted to string
        self.assertEqual(result["cn"], "TestUser")

    def test_applyFormatters_with_userAccountControl_single_value(self):
        """Test applyFormatters with userAccountControl attribute as single-item list"""
        attributes = {
            "cn": [b"Test"],
            "userAccountControl": [b"512"]  # NORMAL_ACCOUNT in list
        }
        formatter_map = formatters.getFormatters()
        
        result = formatters.applyFormatters(attributes, formatter_map)
        
        # cn should be formatted by badldap
        self.assertEqual(result["cn"], "Test")
        # userAccountControl should be formatted as a list by bloodyAD custom formatter
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
            "cn": [b"Test"],
            "userAccountControl": [b"512"]
        }
        
        result = formatters.applyFormatters(attributes, {})
        
        # All attributes should remain unchanged
        self.assertEqual(result, attributes)


if __name__ == '__main__':
    unittest.main()
