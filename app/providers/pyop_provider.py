import os

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from jwcrypto.jwt import JWK
from jwkest.jwk import RSAKey
from pyop.provider import Provider as PyopProvider
from pyop.authz_state import AuthorizationState

from app.misc.utils import kid_from_certificate


# pylint:disable=too-few-public-methods
class MaxPyopProvider(PyopProvider):
    def __init__(
        self,
        signing_key: RSAKey,
        configuration_information,
        authz_state: AuthorizationState,
        clients,
        userinfo,
        *,
        id_token_lifetime=3600,
        extra_scopes=None,
        trusted_certificates_directory=None,
    ):
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
                if filename.endswith(".crt"):
                    with open(
                        os.path.join(trusted_certificates_directory, filename),
                        "r",
                        encoding="utf-8",
                    ) as file:
                        cert_str = file.read()
                        if cert_str.startswith("-----BEGIN CERTIFICATE-----"):
                            cert_obj = load_pem_x509_certificate(
                                str.encode(cert_str), default_backend()
                            )
                            crt = JWK.from_pem(str.encode(cert_str))
                            kid = kid_from_certificate(cert_str)
                            crt.kid = kid
                            if "alg" not in crt:
                                crt.alg = "RS256"

                            self._jwks_certs["keys"].append(crt)
                            self._keys[kid] = cert_obj.public_key()

    @property
    def jwks(self):
        return self._jwks_certs

    def get_subject_identifier_from_authz_state(self, authorization_code: str) -> str:
        """
        A wrapper method that gets the subject identifier from the puop authorization state
        See Pypp do_code_exchange private method for mode details
        """
        return self.authz_state.get_subject_identifier_for_code(authorization_code)
