# pylint: disable=c-extension-no-member
import textwrap
from typing import Dict, Tuple, Any, Union, List

import lxml
import xmlsec
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from lxml import etree

from app.models.saml.constants import NAMESPACES

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"


def get_loc_bind(element) -> Dict[str, str]:
    location = element.get("Location")
    binding = element.get("Binding")
    return {"location": location, "binding": binding}


def has_valid_signature(
    root,
    signature_node,
    cert_data: Union[str, None] = None,
    cert_path: str = "saml/certs/sp.crt",
):
    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    if cert_data is None:
        key = xmlsec.Key.from_file(cert_path, xmlsec.constants.KeyDataFormatCertPem)
    else:
        key = xmlsec.Key.from_memory(cert_data, xmlsec.constants.KeyDataFormatCertPem)
    # Set the key on the context.
    ctx.key = key
    ctx.register_id(root)
    ctx.verify(signature_node)


def get_referred_node(root, signature_node):
    referer_node = signature_node.find(".//dsig:Reference", NAMESPACES)
    referrer_id = referer_node.attrib["URI"][1:]
    if "ID" in root.attrib and root.attrib["ID"] == referrer_id:
        return root
    return root.find(f'.//*[@ID="{referrer_id}"]', NAMESPACES)


def get_parents(node: etree.Element) -> List[etree.Element]:
    parent = node.getparent()
    parents = []
    while parent is not None:
        parents.append(parent)
        parent = parent.getparent()
    return parents


def is_advice_node(node: etree.Element, advice_nodes: List[etree.Element]):
    for parent in get_parents(node):
        if parent in advice_nodes:
            return True
    return False


def has_valid_signatures(
    root: lxml.etree,
    cert_data: Union[str, None] = None,
    cert_path: str = "saml/certs/sp.crt",
) -> Tuple[Any, bool]:
    signature_nodes: List[etree.Element] = root.findall(".//dsig:Signature", NAMESPACES)
    advice_nodes: List[etree.Element] = root.findall(".//saml2:Advice", NAMESPACES)
    for node in signature_nodes:
        try:
            if node.find(".//dsig:DigestValue", NAMESPACES).text is None:
                continue

            if is_advice_node(node, advice_nodes):
                continue

            referred_node = get_referred_node(root, node)
            has_valid_signature(
                referred_node, node, cert_data=cert_data, cert_path=cert_path
            )
        except xmlsec.VerificationError:
            return None, False

    return get_referred_node(root, signature_nodes[0]), True


def remove_padding(enc_data: bytes) -> bytes:
    return enc_data[: -enc_data[-1]]


def compute_keyname(cert):
    cert = load_certificate(FILETYPE_PEM, cert)
    sha256_fingerprint = cert.digest("sha256").decode().replace(":", "").lower()
    return sha256_fingerprint


def enforce_cert_newlines(cert_data):
    return "\n".join(textwrap.wrap(cert_data.replace("\n", ""), 64))


def to_soap_envelope(node):
    ns_map = {"env": SOAP_NS}

    env = etree.Element(etree.QName(SOAP_NS, "Envelope"), nsmap=ns_map)
    body = etree.SubElement(env, etree.QName(SOAP_NS, "Body"), nsmap=ns_map)
    body.append(node)

    return env


def find_element_text_if_not_none(root: etree.Element, path) -> Union[str, None]:
    element = find_element_if_not_none(root, path)
    return None if element is None else element.text


def find_element_if_not_none(root: etree.Element, path) -> Union[etree.Element, None]:
    if root is not None and root.find(path, NAMESPACES) is not None:
        return root.find(path, NAMESPACES)
    return None


def status_from_value(element: etree.Element) -> str:
    return element.attrib["Value"].split(":")[-1]


def status_from_element(element: etree.Element) -> str:
    status = status_from_value(element)
    if status.lower() != "success":
        inner_status_code_element = element.find("./samlp:StatusCode", NAMESPACES)
        if inner_status_code_element is not None:
            status = status_from_value(inner_status_code_element)
    return status
