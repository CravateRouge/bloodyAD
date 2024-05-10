import unittest
from bloodyAD import asciitree


class UnitTests(unittest.TestCase):
    def test_01TreeDisplay(self):
        trust_dict = trust_dict = {
            "child.bloody.lab": {
                "bloody.lab": {
                    "distinguishedName": (
                        "CN=bloody.lab,CN=System,DC=child,DC=bloody,DC=lab"
                    ),
                    "trustDirection": [b"3"],
                    "trustPartner": [b"bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                }
            },
            "cousin.corp": {
                "bloody.lab": {
                    "distinguishedName": "CN=bloody.lab,CN=System,DC=cousin,DC=corp",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                }
            },
            "stranger.lab": {
                "bloody.lab": {
                    "distinguishedName": "CN=bloody.lab,CN=System,DC=stranger,DC=lab",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"8"],
                },
                "cousin.corp": {
                    "distinguishedName": "CN=cousin.corp,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"1"],
                    "trustPartner": [b"cousin.corp"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                },
                "business.corp": {
                    "distinguishedName": "CN=business.corp,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"1"],
                    "trustPartner": [b"business.corp"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                },
            },
            "bloody.lab": {
                "child.bloody.lab": {
                    "distinguishedName": (
                        "CN=child.bloody.lab,CN=System,DC=bloody,DC=lab"
                    ),
                    "trustDirection": [b"3"],
                    "trustPartner": [b"child.bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                },
                "cousin.corp": {
                    "distinguishedName": "CN=cousin.corp,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"cousin.corp"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"0"],
                },
                "stranger.lab": {
                    "distinguishedName": "CN=stranger.lab,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"stranger.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"8"],
                },
            },
        }
        trust_root_domain = "bloody.lab"
        tree = {}
        asciitree.branchFactory({":" + trust_root_domain: tree}, [], trust_dict)
        tree_printer = asciitree.LeftAligned()
        print(tree_printer({trust_root_domain: tree}))
