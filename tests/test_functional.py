import unittest, subprocess, pathlib, json, hashlib, os

class TestModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf = json.loads((pathlib.Path(__file__).parent / "secrets.json").read_text())
        cls.domain = conf['domain']
        cls.host = conf['pdc']['ip']
        cls.admin = {
            'username' : conf['admin_user']['username'],
            'password' : conf['admin_user']['password']
        }
        cls.toTear = []
        cls.env = os.environ.copy()
        cls.bloody_prefix = ["python3", "bloodyAD.py", "--host", cls.host, "-d", cls.domain]
        cls.user = None


    def test_01Auth(self):
        username_pass = ["-u", self.admin['username'], "-p"]
        
        cleartext = username_pass + [self.admin['password']]
        ntlm = username_pass + [f":{hashlib.new('md4',self.admin['password'].encode('utf-16le')).hexdigest()}"]

        self.launchProcess(["getTGT.py", "-dc-ip", self.host, f"{self.domain}/{self.admin['username']}:{self.admin['password']}"])

        self.env["KRB5CCNAME"] = f"{self.admin['username']}.ccache"
        krb = ["-k"]

        cert = ["-c", ":Administrator.pem"]

        auths = [cleartext, ntlm, krb, cert]
        for auth in auths:
            for sec_state in ["","-s "]:
                self.launchProcess(self.bloody_prefix + auth + (sec_state + "getObjectAttributes Administrator sAMAccountName").split(' '))

    def test_02CreateUser(self):
        self.__class__.user = {
            "username" : "stan.dard",
            "password" : "Password123!"
        }
        self.launchBloody(self.admin, ["addUser", self.user["username"], self.user["password"]])
        self.toTear.append(self.test_99RemoveUser)
    

    def test_99RemoveUser(self):
        self.toTear.pop()
        self.launchBloody(self.admin, ["delObject", self.user["username"]])
    

    @classmethod
    def tearDownClass(cls):
        while len(cls.toTear):
            (cls.toTear.pop())()


    def launchBloody(self, creds, args):
        cmd_creds = ["-u",creds["username"],"-p",creds["password"]]
        return self.launchProcess(self.bloody_prefix + cmd_creds + args)


    def launchProcess(self, cmd):
        out, err = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=self.env).communicate()
        out = out.decode()      
        self.assertTrue(out, self.printErr(err.decode(), cmd))
        print(out)
        return out
    

    def printErr(self, err, cmd):
        err = err.replace('\n', '\n ')
        self.err = f"here is the error output ->\n\n {cmd}\n{err}"
        return self.err


if __name__ == '__main__':
    unittest.main(failfast=True)