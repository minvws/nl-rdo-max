# pylint: disable=c-extension-no-member
import copy

from lxml import etree
import xmlsec

def get_loc_bind(element):
    location = element.get('Location')
    binding = element.get('Binding')
    return {
        'location': location,
        'binding': binding
    }

def has_valid_signature(root, cert_data=None, cert_path='saml/certs/sp.crt'):
    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()

    if cert_data is None:
        key = xmlsec.Key.from_file(cert_path, xmlsec.constants.KeyDataFormatCertPem)
    else:
        key = xmlsec.Key.from_memory(cert_data, xmlsec.constants.KeyDataFormatCertPem)
    # Set the key on the context.
    ctx.key = key
    ctx.register_id(root)
    try:
        ctx.verify(signature_node)
        return True
    except xmlsec.VerificationError as verification_error:
        return False

def remove_padding(enc_data):
    return enc_data[:-enc_data[-1]]
