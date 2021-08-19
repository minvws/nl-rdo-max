from inge6.saml.metadata import IdPMetadata

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
