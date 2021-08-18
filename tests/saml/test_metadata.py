from inge6.saml.metadata import IdPMetadata
from inge6.config import settings

# pylint: disable=unused-argument
def test_idp_metadata_bindings_tvs(tvs_config):
    """
    test metadata provided by tvs
    """
    IdPMetadata.IDP_PATH = settings.saml.idp_metadata_path
    idp_metadata = IdPMetadata()
    assert idp_metadata.get_sso(binding='POST')['binding'].endswith('POST')
    assert idp_metadata.get_sso(binding='POST')['location'] != ""

# pylint: disable=unused-argument
def test_idp_metadata_bindings_digid(digid_config):
    """
    test metadata provided by digid
    """
    IdPMetadata.IDP_PATH = settings.saml.idp_metadata_path
    idp_metadata = IdPMetadata()
    assert idp_metadata.get_sso(binding='Redirect')['binding'].endswith('Redirect')
    assert idp_metadata.get_sso(binding='Redirect')['location'] != ""
