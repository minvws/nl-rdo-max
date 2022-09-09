import pytest

from inge6.saml.metadata import IdPMetadata
from inge6.saml.constants import NAMESPACES
from inge6.saml.id_provider import IdProvider

# pylint: disable=unused-argument
def test_idp_metadata_bindings_tvs(tvs_config):
    """
    test metadata provided by tvs
    """
    idp_metadata = IdPMetadata(
        "tests/resources/sample_messages/idp_metadata_authnpost.xml"
    )
    assert idp_metadata.get_sso(binding="POST")["binding"].endswith("POST")
    assert idp_metadata.get_sso(binding="POST")["location"] != ""


# pylint: disable=unused-argument
def test_idp_metadata_bindings_digid(digid_config):
    """
    test metadata provided by digid
    """
    idp_metadata = IdPMetadata(
        "tests/resources/sample_messages/idp_metadata_authnredirect.xml"
    )
    assert idp_metadata.get_sso(binding="Redirect")["binding"].endswith("Redirect")
    assert idp_metadata.get_sso(binding="Redirect")["location"] != ""


def test_metadata_required_root_attrs(tvs_config, tvs_provider_settings, jinja_env):

    tvs_provider = IdProvider("tvs", tvs_provider_settings, jinja_env)
    assert tvs_provider.sp_metadata.root.attrib["entityID"] is not None
    with pytest.raises(KeyError):
        # pylint: disable=pointless-statement
        tvs_provider.sp_metadata.root.attrib["EntityID"]

    assert tvs_provider.sp_metadata.root.attrib["ID"] is not None
    assert tvs_provider.sp_metadata.root.find("./ds:Signature", NAMESPACES) is not None
    assert (
        tvs_provider.sp_metadata.root.find(
            './/md:KeyDescriptor[@use="encryption"]', NAMESPACES
        )
        is not None
    )
    assert (
        tvs_provider.sp_metadata.root.find(
            './/md:KeyDescriptor[@use="signing"]', NAMESPACES
        )
        is not None
    )


def test_metadata_clustered(tvs_config, tvs_clustered_provider_settings, jinja_env):
    tvs_provider = IdProvider("tvs", tvs_clustered_provider_settings, jinja_env)
    assert tvs_provider.sp_metadata.root.attrib["ID"] is not None
    assert (
        tvs_provider.sp_metadata.root.tag
        == "{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor"
    )

    entity_descriptors = tvs_provider.sp_metadata.root.findall(
        ".//md:EntityDescriptor", NAMESPACES
    )
    assert len(entity_descriptors) == 2

    lc_entity_descriptor = None
    dv_entity_descriptor = None
    for entity_descriptor in entity_descriptors:
        assert entity_descriptor.find("./md:SPSSODescriptor", NAMESPACES) is not None
        if "DV" in entity_descriptor.attrib["entityID"]:
            dv_entity_descriptor = entity_descriptor

        if "LC" in entity_descriptor.attrib["entityID"]:
            lc_entity_descriptor = entity_descriptor

    assert lc_entity_descriptor is not None and dv_entity_descriptor is not None
    assert lc_entity_descriptor.find(
        ".//AssertionConsumerService", NAMESPACES
    ) == dv_entity_descriptor.find(".//AssertionConsumerService", NAMESPACES)
