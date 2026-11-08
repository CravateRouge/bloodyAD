"""Tests for LDAP filter escaping in bloodyAD.utils.

``LazyAdSchema._resolveAll`` builds one OR filter out of up to 512
``(distinguishedName=...)`` clauses and sends it in a single search. If any
value in it is not escaped, the whole request fails and *every* DN stays
unresolved, so ``process_members`` silently drops every group member -- which
is how a group can end up with no Members in a BloodHound dump
(CravateRouge/bloodyAD#107).

Before this change the transformation existed only inline in
``cli_modules/add.py`` and omitted ``!``.
"""
import unittest

from bloodyAD.utils import escape_filter_chars


class EscapeFilterCharsTests(unittest.TestCase):
    def test_parentheses_are_escaped(self):
        # Unescaped, these close the filter early: (dn=CN=Group (Old))
        self.assertEqual(escape_filter_chars("CN=Group (Old)"), r"CN=Group \28Old\29")

    def test_asterisk_is_escaped(self):
        self.assertEqual(escape_filter_chars("a*b"), r"a\2ab")

    def test_backslash_is_escaped(self):
        self.assertEqual(escape_filter_chars("c\\d"), r"c\5cd")

    def test_nul_is_escaped(self):
        self.assertEqual(escape_filter_chars("e\x00f"), r"e\00f")

    def test_exclamation_is_escaped(self):
        # Not required by RFC 4515, but filtercomp opens a negation with it.
        self.assertEqual(
            escape_filter_chars("CN=!svc_something,OU=PAM T0,DC=x"),
            r"CN=\21svc_something,OU=PAM T0,DC=x",
        )

    def test_plain_value_is_untouched(self):
        self.assertEqual(escape_filter_chars("plain"), "plain")

    def test_ordinary_distinguished_name_is_untouched(self):
        dn = "CN=Domain Admins,CN=Users,DC=dc,DC=local"
        self.assertEqual(escape_filter_chars(dn), dn)

    def test_non_string_is_returned_as_is(self):
        sentinel = object()
        self.assertIs(escape_filter_chars(sentinel), sentinel)

    def test_escaped_value_has_no_bare_delimiters(self):
        """A value may not contain an unescaped '(' or ')' at all.

        Counting parentheses is not the right check: "(Old)" is balanced but
        still illegal inside an assertion value, because the parser has
        already committed to reading a value when it reaches the '('.
        """
        dn = "CN=Group (Old),OU=Users,DC=x"

        self.assertIn("(", dn)
        self.assertIn(")", dn)

        escaped = escape_filter_chars(dn)
        self.assertNotIn("(", escaped)
        self.assertNotIn(")", escaped)
        self.assertIn(r"\28", escaped)
        self.assertIn(r"\29", escaped)

        # And the assembled clause must hold exactly one pair of delimiters.
        clause = "(distinguishedName=%s)" % escaped
        self.assertEqual(clause.count("("), 1)
        self.assertEqual(clause.count(")"), 1)


class ResolveAllFilterTests(unittest.TestCase):
    def test_dn_clause_uses_the_escaper(self):
        """The clause built by _resolveAll must route the DN through it."""
        import inspect

        from bloodyAD import utils

        source = inspect.getsource(utils.LazyAdSchema._resolveAll)
        self.assertIn("escape_filter_chars(dn)", source)
        self.assertNotIn("f\"(distinguishedName={dn})\"", source)


class AddModuleTests(unittest.TestCase):
    def test_add_uses_the_shared_helper(self):
        """add.py used to carry its own copy that omitted '!'."""
        import inspect

        from bloodyAD.cli_modules import add

        source = inspect.getsource(add)
        self.assertIn("utils.escape_filter_chars(name)", source)
        self.assertNotIn('.replace("*", r"\\2a")', source)


if __name__ == "__main__":
    unittest.main()
