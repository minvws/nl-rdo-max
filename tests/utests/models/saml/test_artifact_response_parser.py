import json

from freezegun import freeze_time
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.misc.utils import file_content_raise_if_none
from app.models.saml.artifact_response import ArtifactResponse
from lxml import etree
from packaging.version import parse as version_parse

from app.models.saml.metadata import SPMetadata, IdPMetadata


def create_artifact_response(
    artifact_response_str: str,
    priv_key_path: str = "tests/resources/secrets/sp.key",
    expected_entity_id: str = "expected_entity_id",
    expected_service_uuid: str = "expected_service_uuid",
    expected_response_destination: str = "expected_response_destination",
    override_expected_issuer: str = None,
    idp_settings_path: str = "tests/resources/test_settings.json",
    templates_path: str = "saml/templates/xml",
    is_verified: bool = True,
    strict: bool = True,
) -> ArtifactResponse:
    artifact_response_str = artifact_response_str.split(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
    )[-1]
    artifact_tree = (
        etree.fromstring(artifact_response_str)  # pylint: disable=c-extension-no-member
        .getroottree()
        .getroot()
    )
    artifact_tree = artifact_tree.find(
        ".//{http://schemas.xmlsoap.org/soap/envelope/}Body/{urn:oasis:names:tc:SAML:2.0:protocol}ArtifactResponse"
    )
    jinja_env = Environment(
        loader=FileSystemLoader(templates_path),
        autoescape=select_autoescape(),
    )
    with open(idp_settings_path, encoding="utf-8") as idp_settings:
        settings = json.loads(idp_settings.read())
    sp_settings = settings.get("sp", {})
    client_cert_with_key = (
        sp_settings.get("cert_path"),
        sp_settings.get("key_path"),
    )
    sp_metadata = SPMetadata(settings, client_cert_with_key, jinja_env)
    idp_metadata = IdPMetadata(settings.get("idp", {}).get("metadata_path"))
    if override_expected_issuer:
        idp_metadata.entity_id = override_expected_issuer
    return ArtifactResponse(
        artifact_response_str=artifact_response_str,
        artifact_tree=artifact_tree,
        cluster_priv_key=None,
        priv_key=file_content_raise_if_none(priv_key_path),
        expected_entity_id=expected_entity_id,
        expected_service_uuid=expected_service_uuid,
        expected_response_destination=expected_response_destination,
        sp_metadata=sp_metadata,
        idp_metadata=idp_metadata,
        saml_specification_version=version_parse(
            str(settings.get("saml_specification_version"))
        ),
        is_verified=is_verified,
        strict=strict,
    )


@freeze_time("2023-03-28T07:41:00Z")
def test_artifact_cluster_response(priv_key_path):
    with open(
        "tests/resources/sample_messages/cluster_response.xml",
        "r",
        encoding="utf-8",
    ) as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    art_resp = create_artifact_response(
        artifact_response_str=art_resp_resource,
        expected_response_destination="https://endpoint.example/acs",
        expected_service_uuid="c57ec6e6-baba-472d-9db4-5ef8cf5e29c8",
        expected_entity_id="urn:nl-eid-gdi:1.0:LC:00000000000000000000:entities:0000",
    )

    assert art_resp.status == "saml_success"


@freeze_time("2021-08-17T14:05:29Z")
def test_artifact_response_request_denied(priv_key_path):
    with open(
        "tests/resources/sample_messages/request_denied.xml",
        "r",
        encoding="utf-8",
    ) as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    art_resp = create_artifact_response(
        artifact_response_str=art_resp_resource,
        expected_response_destination="https://endpoint.example/acs",
        expected_service_uuid="c57ec6e6-baba-472d-9db4-5ef8cf5e29c8",
        expected_entity_id="urn:nl-eid-gdi:1.0:LC:00000000000000000000:entities:0000",
        override_expected_issuer="https://issuer-endpoint.example/saml/idp/metadata",
    )

    assert art_resp.status == "saml_request_denied"


@freeze_time("2023-03-28T14:09:30Z")
def test_artifact_response_login_cancelled(priv_key_path):
    with open(
        "tests/resources/sample_messages/login_cancelled.xml",
        "r",
        encoding="utf-8",
    ) as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    art_resp = create_artifact_response(
        artifact_response_str=art_resp_resource,
        expected_response_destination="https://endpoint.example/acs",
        expected_service_uuid="c57ec6e6-baba-472d-9db4-5ef8cf5e29c8",
        expected_entity_id="urn:nl-eid-gdi:1.0:LC:00000000000000000000:entities:0000",
    )

    assert art_resp.status == "saml_authn_failed"
    assert art_resp.status_message == "Authentication cancelled"
