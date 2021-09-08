import pytest

@pytest.fixture
def tvs_provider_settings():
    return {
        "saml_specification_version": 4.5,
        "base_dir": "saml/tvs",
        "cert_path": "saml/tvs/certs/sp.crt",
        "key_path": "saml/tvs/certs/sp.key",
        "settings_path": "saml/tvs/settings.json",
        "idp_metadata_path": "saml/tvs/metadata/idp_metadata.xml"
    }


@pytest.fixture
def digid_provider_settings():
    return {
        "saml_specification_version": 3.5,
        "base_dir": "saml/digid",
        "cert_path": "saml/digid/certs/sp.crt",
        "key_path": "saml/digid/certs/sp.key",
        "settings_path": "saml/digid/settings.json",
        "idp_metadata_path": "saml/digid/metadata/idp_metadata.xml"
    }
