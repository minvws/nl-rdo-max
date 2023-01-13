import base64
import json
from os import path
from typing import Union, List, Dict, Any

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"


# todo: Test module!
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


def as_bool(input_str: str) -> bool:
    if input_str is not None:
        return isinstance(input_str, str) and input_str.lower() == "true"
    return False


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


def dict_intersection(dict_a: Dict[Any, Any], dict_b: Dict[Any, Any]) -> Dict[Any, Any]:
    return_dict = {}
    for key in dict_a:
        value = None
        if key in dict_b:
            if isinstance(dict_a[key], type(dict_b[key])):
                if type(dict_a[key]) is dict:
                    value = dict_intersection(dict_a[key], dict_b[key])
                if type(dict_a[key]) is list:
                    value = [x for x in dict_a[key] if x in dict_b[key]]
                if dict_a[key] == dict_b[key]:
                    value = dict_a[key]
        if value is not None and value != {} and value != []:
            return_dict[key] = value
    return return_dict


def extract_error_uri_from_state(clients: dict, state: str) -> Union[str, None]:
    client_id = json.loads(base64.b64decode(state))["client_id"]
    if client_id in clients:
        return clients[client_id]["error_page"]
    return None
