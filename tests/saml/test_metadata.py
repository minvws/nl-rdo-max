
# pylint: disable=unused-argument
def test_idp_metadata_bindings_tvs(tvs_config):
    """
    test metadata provided by tvs
    """
    # pylint: disable=import-outside-toplevel
    # reason: fixture before initiating static values
    from inge6.saml.metadata import IdPMetadata
    idp_metadata = IdPMetadata()
    assert idp_metadata.get_sso(binding='Redirect')['binding'].endswith('POST')
    assert idp_metadata.get_sso(binding='Redirect')['location'] != ""

# pylint: disable=unused-argument
def test_idp_metadata_bindings_digid(digid_config):
    """
    test metadata provided by digid
    """
    # pylint: disable=import-outside-toplevel
    # reason: fixture before initiating static values
    from inge6.saml.metadata import IdPMetadata
    idp_metadata = IdPMetadata()
    assert idp_metadata.get_sso(binding='Redirect')['binding'].endswith('Redirect')
    assert idp_metadata.get_sso(binding='Redirect')['location'] != ""
