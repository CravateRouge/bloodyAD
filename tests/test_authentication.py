import unittest
import subprocess
import os
import sys
import json
from pathlib import Path
from bloodyAD.main import main as bloodyAD_main  # Import the main function of bloodyAD

class TestBloodyADAuthentications(unittest.TestCase):
    base_command = ""
    get_object_command = "get object Administrator --attr name"
    tmp_dir = Path(__file__).parent / "tmp"
    crtpass = "P@ssw0rd"

    @staticmethod
    def run_subprocess(command, cwd=None):
        """
        Helper function to run a subprocess command and return its output and exit code.
        """
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Command failed: {command}\n{result.stderr}")
        return result.stdout.strip()

    @classmethod
    def setUpClass(cls):
        """
        Set up required files and configurations for the tests.
        """
        # Create tmp directory
        cls.tmp_dir.mkdir(exist_ok=True)

        # Load credentials from secrets.json
        secrets_path = Path(__file__).parent / "secrets.json"
        with secrets_path.open() as f:
            cls.secrets = json.load(f)

        cls.domain = cls.secrets["domain"]
        cls.dc_ip = cls.secrets["pdc"]["ip"]
        cls.hostname = cls.secrets["pdc"]["hostname"]
        cls.admin_user = cls.secrets["admin_user"]["username"]
        cls.admin_password = cls.secrets["admin_user"]["password"]

        cls.base_command = f"--host {cls.hostname} --dc-ip {cls.dc_ip} -d {cls.domain} -u {cls.admin_user} -v DEBUG"

        cls.pfx_file = cls.tmp_dir / "test.pfx"
        cls.pem_file = cls.tmp_dir / "test.pem"
        cls.pem_with_pass = cls.tmp_dir / "test_with_pass.pem"
        cls.pfx_with_pass = cls.tmp_dir / "test_with_pass.pfx"
        cls.ccache_file = cls.tmp_dir / "test.ccache"
        cls.kirbi_file = cls.tmp_dir / "test.kirbi"
        cls.keytab_file = cls.tmp_dir / "test.keytab"

        # Generate a PFX file using certipy
        certipy_command = (
            f"certipy req -target {cls.dc_ip} -ca bloody-MAIN-CA -template User "
            f"-p '{cls.admin_password}' -debug -u '{cls.admin_user}@{cls.domain}' -out {cls.pfx_file.stem}"
        )
        try:
            cls.run_subprocess(certipy_command, cwd=cls.tmp_dir)
            if not cls.pfx_file.exists():
                raise FileNotFoundError(f"PFX file not created: {cls.pfx_file}")
        except Exception as e:
            raise RuntimeError(f"Failed to generate PFX file. Ensure certipy is installed and configured correctly.\n{e}")

        # Convert the PFX to PEM using OpenSSL
        try:
            cls.run_subprocess(
                f"openssl pkcs12 -in {cls.pfx_file} -out {cls.pem_file} -nodes -passin pass:",
                cwd=cls.tmp_dir,
            )
        except RuntimeError as e:
            raise RuntimeError(f"Failed to convert PFX to PEM. Ensure OpenSSL is installed and configured correctly.\n{e}")

        # Add a password to the PEM file
        cls.run_subprocess(
            f"openssl rsa -in {cls.pem_file} -out {cls.pem_with_pass} -aes256 -passout pass:{cls.crtpass}",
            cwd=cls.tmp_dir,
        )

        # Add a password to the PFX file
        cls.run_subprocess(
            f"openssl pkcs12 -export -in {cls.pem_file} -out {cls.pfx_with_pass} -passout pass:{cls.crtpass}",
            cwd=cls.tmp_dir,
        )

        # Retrieve ccache and kirbi files using minikerberos
        cls.run_subprocess(
            f"python3 /mnt/hgfs/bloodyAD-dev/minikerberos/minikerberos/examples/getTGT.py "
            f"'kerberos+password://{cls.domain}\\{cls.admin_user}:{cls.admin_password}@{cls.dc_ip}' "
            f"--ccache {cls.ccache_file} --kirbi {cls.kirbi_file}",
            cwd=cls.tmp_dir,
        )

    def run_bloodyAD(self, args):
        """
        Helper function to call bloodyAD's argparse directly.
        """
        sys.argv = ["bloodyAD.py"] + args.split()
        try:
            bloodyAD_main()
        except SystemExit as e:
            if e.code != 0:
                print(f"Command failed: {' '.join(sys.argv)}")
                raise

    def test_certificate_authentications(self):
        """
        Test certificate-based authentications.
        """
        cert_commands = [
            f"{self.base_command} -c :{self.pfx_file} {self.get_object_command}",
            f"{self.base_command} -c {self.pfx_file} {self.get_object_command}",
            f"{self.base_command} -p {self.crtpass} -c {self.pfx_with_pass} {self.get_object_command}",
            f"{self.base_command} -c :{self.pem_file} {self.get_object_command}",
            f"{self.base_command} -c {self.pem_file} {self.get_object_command}",
        ]
        for command in cert_commands:
            with self.subTest(command=command):
                try:
                    self.run_bloodyAD(command)
                except Exception as e:
                    print(f"Test failed for command: {command}")
                    raise e

    def test_kerberos_authentications(self):
        """
        Test Kerberos-based authentications.
        """
        kerberos_commands = [
            f"{self.base_command} -k ccache={self.ccache_file} {self.get_object_command}",
            f"{self.base_command} -k kirbi={self.kirbi_file} {self.get_object_command}",
        ]
        for command in kerberos_commands:
            with self.subTest(command=command):
                try:
                    self.run_bloodyAD(command)
                except Exception as e:
                    print(f"Test failed for command: {command}")
                    raise e

    @classmethod
    def tearDownClass(cls):
        """
        Clean up generated files if all tests pass.
        """
        if not any(error for _, error in getattr(cls, '_outcome', unittest.TestResult()).errors):
            for file in cls.tmp_dir.iterdir():
                file.unlink()
            cls.tmp_dir.rmdir()


if __name__ == "__main__":
    unittest.main(failfast=True)