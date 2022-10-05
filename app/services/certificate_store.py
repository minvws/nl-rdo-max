import os
from typing import Union

from cryptography.hazmat.primitives import hashes
from jwcrypto.jwk import JWK


# pylint: disable=too-few-public-methods
class CertificateStore:
    def __init__(self, directory: Union[None, str]):
        self.keys = []
        if directory:
            self.load_certificates(directory)

    def load_certificates(self, directory: str):
        for filename in os.listdir(directory):
            with open(os.path.join(directory, filename), "r", encoding="utf-8") as file:
                kid = filename.rpartition(".")[0]
                key = CertificateStore._create_from_file_content(kid, file.read())
                self.keys.append(key)

    def get_by_thumbprint(self, thumbprint: str) -> JWK:
        for key in self.keys:
            print(key.thumbprint(hashalg=hashes.SHA256()))
            if key.thumbprint(hashalg=hashes.SHA256()) == thumbprint:
                return key

    @classmethod
    def _create_from_file_content(cls, kid, file_content) -> JWK:
        jwk_key = JWK.from_pem(str.encode(file_content))
        jwk_key.kid = kid
        return jwk_key
