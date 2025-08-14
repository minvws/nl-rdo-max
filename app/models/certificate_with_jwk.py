class CertificateWithJWK:
    def __init__(self, certificate, jwk, kid, x5t, pem):
        self.certificate = certificate
        self.jwk = jwk
        self.kid = kid
        self.x5t = x5t
        self.pem = pem
