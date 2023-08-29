import base64
import json
import os
from os import path
from typing import Union, List, Any

from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from fastapi.templating import Jinja2Templates
from Cryptodome.Hash import SHA256
from Cryptodome.IO import PEM

from app.models.uzi_attributes import UziAttributes
from app.dependency_injection.config import get_config

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"

templates = Jinja2Templates(directory="jinja2")
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
    with open(filepath, "r", encoding="utf-8") as json_file:
        return json.loads(json_file.read())


def as_list(input_str: str) -> List[str]:
    return input_str.split(", ")


def as_bool(input_str: Union[str, None]) -> bool:
    return input_str is not None and input_str.lower() == "true"


def clients_from_json(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8") as file:
        return json.load(file)


def read_cert(cert_path: str) -> str:
    with open(cert_path, "r", encoding="utf-8") as cert_file:
        cert_data = strip_cert(cert_file.read())
    return cert_data


def strip_cert(cert_data) -> str:
    return "\n".join(cert_data.strip().split("\n")[1:-1])


def compute_fingerpint(cert: bytes, the_hash: str = "sha256") -> bytes:
    loaded_cert = load_certificate(FILETYPE_PEM, cert)
    return loaded_cert.digest(the_hash).decode().replace(":", "").lower().encode()


def get_fingerprint(signing_cert: bytes) -> bytes:
    sha1_fingerprint = compute_fingerpint(signing_cert, "sha1").decode()
    return base64.urlsafe_b64encode(sha1_fingerprint.encode())


# @TODO : not used anymore, delete?
def extract_error_uri_from_state(clients: dict, state: str) -> Union[str, None]:
    client_id = json.loads(base64.b64decode(state))["client_id"]
    if client_id in clients:
        return clients[client_id]["error_page"]
    return None


def load_template(file_path, filename):
    template_path = os.path.join(file_path, filename)
    with open(template_path, "r", encoding="utf-8") as template_file:
        return template_file.read()


def kid_from_certificate(certificate: str) -> str:
    der = PEM.decode(certificate)
    sha = SHA256.new()
    sha.update(der[0])
    return base64.b64encode(sha.digest()).decode("utf-8")


def mocked_bsn_to_uzi_data(
    bsn: str,
    relation_id_filter: str = None,
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
