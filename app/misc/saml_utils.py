# pylint: disable=c-extension-no-member
import textwrap
from typing import Dict, Tuple, Any, Optional, Union, List

import lxml
import xmlsec
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from lxml import etree

from app.models.saml.constants import NAMESPACES

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"


# todo: Test module! Merge with existing saml utils?
def from_settings(
    settings_dict, selector: str, default: Optional[str] = None
) -> Optional[str]:
    key_hierarchy = selector.split(".")
    value = settings_dict

    key: Union[str, int] = ""
    for key in key_hierarchy:
        try:
            key = int(key)
        except ValueError:
            pass

        try:
            value = value[key]
        except KeyError as _:
            return default
    return value


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
    try:
        for node in signature_nodes:
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