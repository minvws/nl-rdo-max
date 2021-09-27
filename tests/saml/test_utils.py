import base64
import zlib

from inge6.saml.utils import strip_cert

def decode_base64_and_inflate( b64string ):
    decoded_data = base64.b64decode( b64string )
    return zlib.decompress( decoded_data , -15) # pylint: disable=c-extension-no-member

CERT_NEWLINE = """-----BEGIN CERTIFICATE-----
FSGDSGDFGDF
-----END CERTIFICATE-----\n\n"""

CERT_NO_NEWLINE = """-----BEGIN CERTIFICATE-----
FSGDSGDFGDF
-----END CERTIFICATE-----"""

def test_cert_strip():
    assert "END CERTIFICATE" not in strip_cert(CERT_NO_NEWLINE)
    assert "END CERTIFICATE" not in strip_cert(CERT_NEWLINE)
    assert "BEGIN CERTIFICATE" not in strip_cert(CERT_NO_NEWLINE)
    assert "BEGIN CERTIFICATE" not in strip_cert(CERT_NEWLINE)
    assert strip_cert(CERT_NEWLINE) == strip_cert(CERT_NO_NEWLINE)
