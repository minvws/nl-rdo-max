import os

from cryptography.x509 import Certificate
from jwcrypto.jwk import JWK
from jwkest.jwk import RSAKey
from pyop.provider import Provider as PyopProvider
from pyop.authz_state import AuthorizationState

from app.services.encryption.jwt_service import JWT_ALG
from app.misc.utils import (
    jwk_from_certificate,
    read_cert_as_x509_certificate,
)


def _load_certificates_of_directory_as_jwk_for_pyop_provider(
    directory_path: str | None,
) -> list[JWK]:
    if directory_path is None:
        return []

    if not os.path.isdir(directory_path):
        raise ValueError(f"Provided path '{directory_path}' is not a directory.")

    jwks = []

    for filename in os.listdir(directory_path):
        if not filename.endswith(".crt"):
            continue

        file_path = os.path.join(directory_path, filename)
        certificate = read_cert_as_x509_certificate(file_path)
        jwk = _cert_to_jwk_for_pyop(certificate)
        jwks.append(jwk)

    return jwks


def _cert_to_jwk_for_pyop(certificate: Certificate) -> JWK:
    jwk = jwk_from_certificate(certificate)

    if jwk.get("kty") == "RSA" and "alg" not in jwk:
        # The alg parameter is an optional parameter in JWKs, it could be removed in the future.
        # For now, we set it to our default JWT algorithm.
        jwk.update(
            {
                "alg": JWT_ALG,
            }
        )

    return jwk


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

        additional_jwks = _load_certificates_of_directory_as_jwk_for_pyop_provider(
            trusted_certificates_directory
        )
        self._jwks_certs["keys"].extend(additional_jwks)

    @property
    def jwks(self):
        return self._jwks_certs

    def get_subject_identifier_from_authz_state(self, authorization_code: str) -> str:
        """
        A wrapper method that gets the subject identifier from the puop authorization state
        See Pypp do_code_exchange private method for mode details
        """
        return self.authz_state.get_subject_identifier_for_code(authorization_code)
