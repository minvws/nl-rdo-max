import xmlsec

def has_valid_signature(root, cert_path='saml/certs/sp.crt'):
    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(cert_path, xmlsec.constants.KeyDataFormatCertPem)
    # Set the key on the context.
    ctx.key = key
    ctx.register_id(root)
    ctx.verify(signature_node)
    return True
