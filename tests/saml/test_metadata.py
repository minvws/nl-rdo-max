import pytest

from inge6.saml.metadata import IdPMetadata, _strip_cert
from inge6.saml.constants import NAMESPACES
from inge6.saml.id_provider import IdProvider

# pylint: disable=unused-argument
def test_idp_metadata_bindings_tvs(tvs_config):
    """
    test metadata provided by tvs
    """
    idp_metadata = IdPMetadata('tests/resources/idp_metadata_authnpost.xml')
    assert idp_metadata.get_sso(binding='POST')['binding'].endswith('POST')
    assert idp_metadata.get_sso(binding='POST')['location'] != ""

# pylint: disable=unused-argument
def test_idp_metadata_bindings_digid(digid_config):
    """
    test metadata provided by digid
    """
    idp_metadata = IdPMetadata('tests/resources/idp_metadata_authnredirect.xml')
    assert idp_metadata.get_sso(binding='Redirect')['binding'].endswith('Redirect')
    assert idp_metadata.get_sso(binding='Redirect')['location'] != ""

CERT_NEWLINE = """-----BEGIN CERTIFICATE-----
FSGDSGDFGDF
-----END CERTIFICATE-----\n\n"""

CERT_NO_NEWLINE = """-----BEGIN CERTIFICATE-----
FSGDSGDFGDF
-----END CERTIFICATE-----"""

def test_cert_strip():
    assert "END CERTIFICATE" not in _strip_cert(CERT_NO_NEWLINE)
    assert "END CERTIFICATE" not in _strip_cert(CERT_NEWLINE)
    assert "BEGIN CERTIFICATE" not in _strip_cert(CERT_NO_NEWLINE)
    assert "BEGIN CERTIFICATE" not in _strip_cert(CERT_NEWLINE)
    assert _strip_cert(CERT_NEWLINE) == _strip_cert(CERT_NO_NEWLINE)



def test_metadata_required_root_attrs(tvs_config, tvs_provider_settings):
    tvs_provider = IdProvider('tvs', tvs_provider_settings)
    assert tvs_provider.sp_metadata.root.attrib['entityID'] is not None
    with pytest.raises(KeyError):
        tvs_provider.sp_metadata.root.attrib['EntityID'] # pylint: disable=pointless-statement

    assert tvs_provider.sp_metadata.root.attrib['ID'] is not None
    assert tvs_provider.sp_metadata.root.find('./ds:Signature', NAMESPACES) is not None
    assert tvs_provider.sp_metadata.root.find('.//md:KeyDescriptor[@use="encryption"]', NAMESPACES) is not None
    assert tvs_provider.sp_metadata.root.find('.//md:KeyDescriptor[@use="signing"]', NAMESPACES) is not None
