import json
import base64
from os import path
from typing import Union

from lxml import etree
from OpenSSL.crypto import load_certificate, FILETYPE_PEM


SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"


def file_content(filepath: str) -> Union[str, None]:
    if filepath is not None and path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    return None


def as_list(input: str):
    return input.split(", ")


def as_bool(input: str):
    if input is not None:
        return isinstance(input, str) and input.lower() == "true"
    return False


def clients_from_json(filepath: str):
    with open(filepath, "r", encoding="utf-8") as file:
        return json.load(file)


def upper(input: str):
    return input.upper()


def read_cert(cert_path: str) -> None:
    with open(cert_path, "r", encoding="utf-8") as cert_file:
        cert_data = strip_cert(cert_file.read())

    return cert_data


def strip_cert(cert_data):
    return "\n".join(cert_data.strip().split("\n")[1:-1])


def to_soap_envelope(node):
    ns_map = {"env": SOAP_NS}

    env = etree.Element(etree.QName(SOAP_NS, "Envelope"), nsmap=ns_map)
    body = etree.SubElement(env, etree.QName(SOAP_NS, "Body"), nsmap=ns_map)
    body.append(node)

    return env


def compute_fingerpint(cert: bytes, hash: str = "sha256"):
    cert = load_certificate(FILETYPE_PEM, cert)
    return cert.digest(hash).decode().replace(":", "").lower().encode()


def get_fingerprint(signing_cert: bytes):
    sha1_fingerprint = compute_fingerpint(signing_cert, "sha1").decode()
    return base64.urlsafe_b64encode(sha1_fingerprint.encode())
