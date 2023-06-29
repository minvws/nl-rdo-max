import os
import configparser

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from jwcrypto.jwt import JWK
from jwkest.jwk import RSAKey
from pyop.provider import Provider as PyopProvider

from app.misc.utils import get_fingerprint


# pylint:disable=too-few-public-methods
class MaxPyopProvider(PyopProvider):
    def __init__(
        self,
        signing_key: RSAKey,
        configuration_information,
        authz_state,
        clients,
        userinfo,
        *,
        id_token_lifetime=3600,
        extra_scopes=None,
        trusted_certificates_directory=None,
    ):
        signing_key.kid = "oidc_signing_key"

        # TODO: FIX THIS. It totally reloads the config.
        config = configparser.ConfigParser()
        config.read("max.conf")
        signing_cert = str(config["oidc"]["rsa_private_key"]).replace(".key",".crt")
        with open(signing_cert,"r", encoding="utf-8") as file:
            cert_str = file.read()
            skey = JWK.from_pem(str.encode(cert_str))
            signing_key.kid = skey.kid
        # /TODO

        super().__init__(
            signing_key,
            configuration_information,
            authz_state,
            clients,
            userinfo,
            id_token_lifetime=id_token_lifetime,
            extra_scopes=extra_scopes,
        )
        self._jwks_certs = super().jwks  # type:ignore
        if trusted_certificates_directory is not None:
            self._keys = {}
            for filename in os.listdir(trusted_certificates_directory):
                with open(
                    os.path.join(trusted_certificates_directory, filename),
                    "r",
                    encoding="utf-8",
                ) as file:
                    cert_str = file.read()
                    if cert_str.startswith("-----BEGIN PUBLIC KEY-----"):
                        key = JWK.from_pem(str.encode(cert_str))
                        self._jwks_certs["keys"].append(key)
                        self._keys[key.thumbprint(hashes.SHA1())] = key
                    else:
                        sha1 = get_fingerprint(cert_str.encode()).decode()
                        cert_obj = load_pem_x509_certificate(
                            str.encode(cert_str), default_backend()
                        )
                        key = JWK.from_pem(str.encode(cert_str))
                        self._jwks_certs["keys"].append(key)
                        public_key = cert_obj.public_key()
                        self._keys[sha1] = public_key

    @property
    def jwks(self):
        return self._jwks_certs
