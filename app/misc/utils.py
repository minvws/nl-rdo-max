import json
from lxml import etree


SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"


def file_content(filepath: str):
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()


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
