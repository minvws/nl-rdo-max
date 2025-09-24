from cryptography.x509 import Certificate
from jwcrypto.jwk import JWK


class CertificateWithJWK:
    def __init__(
        self, certificate: Certificate, jwk: JWK, kid: str, x5t: str, pem: str
    ):
        self.certificate = certificate
        self.jwk = jwk
        self.kid = kid
        self.x5t = x5t
        self.pem = pem
