import base64
import json
import os
from os import path
from typing import Union, List, Any, Optional, Dict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, ed448, x25519

from cryptography.x509 import Certificate
from jwcrypto.jwk import JWK

from app.models.certificate_with_jwk import CertificateWithJWK
from app.models.uzi_attributes import UziAttributes
from app.dependency_injection.config import get_config

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"

config = get_config()


def file_content(filepath: str) -> Union[str, None]:
    if filepath is not None and path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    return None


def file_content_raise_if_none(filepath: str) -> str:
    optional_file_content = file_content(filepath)
    if optional_file_content is None:
        raise ValueError(f"file_content for {filepath} shouldn't be None")
    return optional_file_content


def json_from_file(filepath: str) -> Any:
    return json.loads(file_content_raise_if_none(filepath))


def as_list(input_str: str) -> List[str]:
    return input_str.split(", ")


def as_bool(input_str: Union[str, None]) -> bool:
    return input_str is not None and input_str.lower() == "true"


def clients_from_json(filepath: str) -> Dict[str, Any]:
    clients: Dict[str, Any] = json_from_file(filepath)

    for client in clients.values():
        client["certificate"] = load_certificate_with_jwk_from_path(
            client["client_certificate_path"]
        )
        del client["client_certificate_path"]

    return clients


def read_cert_as_x509_certificate(cert_path: str) -> Certificate:
    cert_data = file_content_raise_if_none(cert_path)
    return x509.load_pem_x509_certificate(cert_data.encode())


def strip_cert(cert_data) -> str:
    return "\n".join(cert_data.strip().split("\n")[1:-1])


def load_template(file_path, filename):
    template_path = os.path.join(file_path, filename)
    with open(template_path, "r", encoding="utf-8") as template_file:
        return template_file.read()


def load_jwk(filepath: str) -> JWK:
    file = file_content_raise_if_none(filepath)
    return JWK.from_pem(file.encode())


def load_certificate_with_jwk_from_path(filepath: str) -> CertificateWithJWK:
    """
    Load a certificate from the given file path and return it as a CertificateWithJWK object.
    The certificate is expected to be in PEM format.
    """
    certificate = read_cert_as_x509_certificate(filepath)
    return load_certificate_with_jwk(certificate)


def load_certificate_with_jwk(certificate: Certificate) -> CertificateWithJWK:
    """
    Build CertificateWithJWK object based on the provided certificate.
    """
    jwk = jwk_from_certificate(certificate)
    kid = kid_from_certificate(certificate)
    x5t = x5t_from_certificate(certificate)
    pem = strip_cert(pem_from_certificate(certificate))

    return CertificateWithJWK(
        certificate=certificate,
        jwk=jwk,
        kid=kid,
        x5t=x5t,
        pem=pem,
    )


def kid_from_certificate(certificate: Certificate) -> str:
    """
    The "kid" (Key ID) is a unique identifier for the key. There is no standard way to generate a kid.
    This implementation uses the base64-encoded SHA-256 fingerprint of the certificate, it needs
    to match the implementation of the external userinfo service.
    """
    sha256_fingerprint = certificate.fingerprint(hashes.SHA256())
    return base64.b64encode(sha256_fingerprint).decode("utf-8")


def x5t_from_certificate(certificate: Certificate) -> str:
    """
    Generate the "x5t" (X.509 certificate SHA-1 thumbprint) as specified in RFC 7517 section 4.8.
    This is the base64url-encoded SHA-1 digest of the DER encoding of the X.509 certificate.
    See: https://datatracker.ietf.org/doc/html/rfc7517#section-4.8
    See: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
    """
    sha1_fingerprint = certificate.fingerprint(hashes.SHA1())  # nosec B303
    return base64.urlsafe_b64encode(sha1_fingerprint).decode("utf-8")


def jwk_from_certificate(certificate: Certificate) -> JWK:
    """
    Convert a x509 Certificate object to a JWK (JSON Web Key) object.
    """
    public_key = certificate.public_key()

    # Explicitly check the type of the public key for mypy linting instead of catching exception to JWK.from_pyca
    if not isinstance(
        public_key,
        (
            rsa.RSAPublicKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
            x25519.X25519PublicKey,
        ),
    ):
        raise ValueError(
            f"Unsupported public key type in certificate: {type(public_key)}"
        )

    # Convert the public key to JWK format and set the kid and x5t attributes
    jwk = JWK.from_pyca(public_key)
    jwk.update(
        {
            "kid": kid_from_certificate(certificate),
            "x5t": x5t_from_certificate(certificate),
        }
    )
    return jwk


def pem_from_certificate(cert: Certificate) -> str:
    """
    Convert a x509 Certificate object to a PEM-encoded string.
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")


def mocked_bsn_to_uzi_data(
    bsn: str,
    relation_id_filter: Optional[str] = None,
    filepath: str = config.get("app", "mocked_uzi_data_file_path"),
) -> UziAttributes:
    uzi_data = json_from_file(filepath)
    instance = UziAttributes(**uzi_data[bsn])
    if relation_id_filter:
        instance.relations = [
            relation
            for relation in instance.relations
            if relation.ura == relation_id_filter
        ]
    return instance


def get_version_from_file(file_path: Optional[str] = None) -> str:
    _default_version = "v0.0.0"

    if file_path is None:
        return _default_version

    _version_dict = json_from_file(file_path)
    return _version_dict["version"] if "version" in _version_dict else _default_version


def translate(language_key: str, language_map: Dict[str, str]) -> str:
    return language_map.get(language_key, language_key)
