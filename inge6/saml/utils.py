# pylint: disable=c-extension-no-member
from lxml import etree
import xmlsec

from .constants import NAMESPACES

def get_loc_bind(element):
    location = element.get('Location')
    binding = element.get('Binding')
    return {
        'location': location,
        'binding': binding
    }

def has_valid_signature(root, signature_node, cert_data=None, cert_path='saml/certs/sp.crt'):
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
    referer_node = signature_node.find('.//dsig:Reference', NAMESPACES)
    referrer_id = referer_node.attrib['URI'][1:]
    if 'ID' in root.attrib and root.attrib['ID'] == referrer_id:
        return root
    return root.find(f'.//*[@ID="{referrer_id}"]', NAMESPACES)

def has_valid_signatures(root, cert_data=None, cert_path='saml/certs/sp.crt'):
    signature_nodes = root.findall('.//dsig:Signature', NAMESPACES)

    try:
        for node in signature_nodes:

            if node.find('.//dsig:DigestValue', NAMESPACES).text is None:
                continue

            referred_node = get_referred_node(root, node)
            has_valid_signature(referred_node, node, cert_data=cert_data, cert_path=cert_path)
    except xmlsec.VerificationError:
        return None, False

    return get_referred_node(root, signature_nodes[0]), True


def remove_padding(enc_data):
    return enc_data[:-enc_data[-1]]
