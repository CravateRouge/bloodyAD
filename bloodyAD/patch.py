import os
# Waiting for asysocks 0.2.18
from asysocks.unicomm.common.unissl import UniSSL
def pfx_to_pem(self, pfx_path, pfx_password):
    #https://gist.github.com/erikbern/756b1d8df2d1487497d29b90e81f8068
    from pathlib import Path
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
    

    ''' Decrypts the .pfx file to be used with requests. '''
    pfx = Path(pfx_path).read_bytes()
    if isinstance(pfx_password, str):
        pfx_password = pfx_password.encode('utf-8')
    private_key, main_cert, add_certs = load_key_and_certificates(pfx, pfx_password, None)
    suffix = '%s.pem' % os.urandom(4).hex()
    self._UniSSL__keyfilename = 'key_%s' % suffix
    self._UniSSL__certfilename = 'cert_%s' % suffix
    with open(self._UniSSL__keyfilename, 'wb') as f:
        f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    with open(self._UniSSL__certfilename, 'wb') as f:
        f.write(main_cert.public_bytes(Encoding.PEM))
    if len(add_certs) > 0:
        self._UniSSL__cacertfilename = 'cacert_%s' % suffix
        with open(self._UniSSL__cacertfilename, 'wb') as f:
            for ca in add_certs:
                f.write(ca.public_bytes(Encoding.PEM))

UniSSL.pfx_to_pem = pfx_to_pem