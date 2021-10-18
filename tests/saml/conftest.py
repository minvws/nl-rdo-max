import pytest

from jinja2 import Environment, FileSystemLoader, select_autoescape

from inge6.config import settings

@pytest.fixture
def tvs_provider_settings():
    return {
        "saml_specification_version": "4.5",
        "base_dir": "saml/tvs",
        "cert_path": "saml/tvs/certs/sp.crt",
        "key_path": "saml/tvs/certs/sp.key",
        "settings_path": "saml/tvs/settings.json",
        "idp_metadata_path": "saml/tvs/metadata/idp_metadata.xml"
    }

@pytest.fixture
def tvs_clustered_provider_settings():
    return {
        "saml_specification_version": "4.5",
        "base_dir": "tests/resources/saml_provider_settings/tvs_clustered",
        "cert_path": "saml/tvs/certs/sp.crt",
        "key_path": "saml/tvs/certs/sp.key",
        "settings_path": "tests/resources/saml_provider_settings/tvs_clustered/settings.json",
        "idp_metadata_path": "tests/resources/saml_provider_settings/tvs_clustered/metadata/idp_metadata.xml"
    }

@pytest.fixture
def digid_provider_settings():
    return {
        "saml_specification_version": "3.5",
        "base_dir": "saml/digid",
        "cert_path": "saml/digid/certs/sp.crt",
        "key_path": "saml/digid/certs/sp.key",
        "settings_path": "saml/digid/settings.json",
        "idp_metadata_path": "saml/digid/metadata/idp_metadata.xml"
    }

@pytest.fixture
def jinja_env():
    return Environment(
        loader=FileSystemLoader(settings.saml.templates),
        autoescape=select_autoescape()
    )