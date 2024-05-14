from enum import Enum

NAMESPACES = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "dsig": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
}


class SectorNumber(Enum):
    BSN = 1
    SOFI = 2


SECTOR_CODES = {
    "s00000000": SectorNumber.BSN,
    "s00000001": SectorNumber.SOFI,
}
