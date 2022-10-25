from pyop.provider import Provider as PyopProvider
import os
from jwcrypto.jwt import JWK, JWT
from cryptography.x509 import load_pem_x509_certificate, SubjectKeyIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from app.misc.utils import get_fingerprint


class MaxPyopProvider(PyopProvider):
    def __init__(self, signing_key, configuration_information, authz_state, clients, userinfo, *,
                 id_token_lifetime=3600, extra_scopes=None, trusted_certificates_directory=None):
        super().__init__(signing_key, configuration_information, authz_state, clients, userinfo,
                         id_token_lifetime=id_token_lifetime, extra_scopes=extra_scopes)
        self._jwks_certs = super().jwks
        self._jwks_certs["keys"][0]["kid"] = "oidc_signing_key"
        if trusted_certificates_directory is not None:
            self._keys = {}
            for filename in os.listdir(trusted_certificates_directory):
                with open(os.path.join(trusted_certificates_directory, filename), 'r') as file:
                    cert_str = file.read()
                    try:
                        if cert_str.startswith('-----BEGIN PUBLIC KEY-----'):
                            key = JWK.from_pem(str.encode(cert_str))
                            self._jwks_certs["keys"].append(key)
                            self._keys[key.thumbprint(hashes.SHA1())] = key
                        else:
                            sha1 = get_fingerprint(cert_str.encode()).decode()
                            cert_obj = load_pem_x509_certificate(str.encode(cert_str), default_backend())
                            key = JWK.from_pem(str.encode(cert_str))
                            self._jwks_certs["keys"].append(key)
                            public_key = cert_obj.public_key()
                            self._keys[sha1] = public_key
                    except Exception as e:
                        raise e

    @property
    def jwks(self):
        return self._jwks_certs
