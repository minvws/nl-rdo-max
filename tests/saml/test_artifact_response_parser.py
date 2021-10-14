# pylint: disable=c-extension-no-member
from datetime import datetime, timedelta

import pytest

from freezegun import freeze_time
from lxml import etree
from packaging.version import Version
from inge6.config import get_settings

from inge6.saml import ArtifactResponse
from inge6.saml.id_provider import IdProvider
from inge6.saml.provider import Provider as SAMLProvider
from inge6.saml.exceptions import UserNotAuthenticated
from inge6.saml.constants import NAMESPACES

from ..utils import PRIV_KEY_BSN_AES_KEY

# pylint: disable=pointless-string-statement
"""
    We have multiple test files in the resources folder, as we are not allowed to communicate with the SAML Provider directly
    we have some edited files with custom keys. This, inherently, means that signature validation will fail on those files.
    For that purpose we have several files, each with its own purpose.

    Specifically for the BSN decryption test, we have reencrypted the AES key with a random keypair of which the private key
    is pasted as a string in the variable `PRIV_KEY_BSN_AES_KEY`.
"""


def update_time_values(xml_str):
    root = etree.fromstring(xml_str)
    strformat = '%Y-%m-%dT%H:%M:%S.%f%z'
    current_time = datetime.now()

    datetime_elems = root.findall('.//*[@IssueInstant]')
    for elem in datetime_elems:
        elem.attrib['IssueInstant'] = current_time.strftime(strformat)

    datetime_elems = root.findall('.//*[@NotBefore]')
    for elem in datetime_elems:
        not_before_time = current_time - timedelta(seconds=120)
        elem.attrib['NotBefore'] = not_before_time.strftime(strformat)

    datetime_elems = root.findall('.//*[@NotOnOrAfter]')
    for elem in datetime_elems:
        not_on_or_after_time = current_time + timedelta(seconds=120)
        elem.attrib['NotOnOrAfter'] = not_on_or_after_time.strftime(strformat)

    authn_instants = root.findall('.//saml:AuthnStatement', NAMESPACES)
    for elem in authn_instants:
        elem.attrib['AuthnInstant'] = current_time.strftime(strformat)

    return etree.tostring(root).decode()


@pytest.fixture
def response_custom_bsn_tvs():
    with open('tests/resources/artifact_response_custom_bsn.xml', 'r', encoding='utf-8') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()
    return art_resp_resource

@pytest.fixture
def response_unedited_tvs():
    with open('tests/resources/artifact_response.xml', 'r', encoding='utf-8') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()
    return art_resp_resource

@pytest.fixture
def response_authn_failed_tvs():
    with open('tests/resources/artifact_resolve_response_authnfailed.xml', 'r', encoding='utf-8') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()
    return art_resp_resource

@pytest.fixture
def saml_provider():
    return SAMLProvider(settings=get_settings())

@freeze_time("2021-06-01 12:44:06")
# pylint: disable=redefined-outer-name
def test_get_bsn_tvs(response_custom_bsn_tvs, monkeypatch, tvs_provider_settings, jinja_env):
    tvs_provider = IdProvider(get_settings(), 'tvs', tvs_provider_settings, jinja_env)
    artifact_response = ArtifactResponse.from_string(get_settings(), response_custom_bsn_tvs, tvs_provider, insecure=True)

    monkeypatch.setattr(tvs_provider, 'priv_key', PRIV_KEY_BSN_AES_KEY)
    assert artifact_response.get_bsn() == '900212640'

@freeze_time("2021-08-18 16:35:24.335248")
# pylint: disable=redefined-outer-name
def test_from_string_tvs(response_unedited_tvs, tvs_provider_settings, jinja_env):
    tvs_provider = IdProvider(get_settings(), 'tvs', tvs_provider_settings, jinja_env)
    ArtifactResponse.from_string(get_settings(), response_unedited_tvs, tvs_provider, is_test_instance=True)
    assert True

# pylint: disable=redefined-outer-name
@freeze_time("2021-06-06 11:40:11")
def test_authnfailed_tvs(response_authn_failed_tvs, tvs_provider_settings, jinja_env):
    tvs_provider = IdProvider(get_settings(), 'tvs', tvs_provider_settings, jinja_env)
    with pytest.raises(UserNotAuthenticated):
        ArtifactResponse.from_string(get_settings(), response_authn_failed_tvs, tvs_provider, insecure=True).raise_for_status()


@freeze_time("2021-08-17T14:05:29Z")
def test_artifact_response_parse_digid(mocker, digid_provider_settings, jinja_env):
    with open('tests/resources/artifact_response_digid.xml', 'r', encoding='utf-8') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    digid_provider = IdProvider(get_settings(), 'digid', digid_provider_settings, jinja_env)
    mocker.patch.dict(digid_provider.settings_dict, {
        'sp': {
            'entityId': 'https://siam1.test.anoigo.nl/aselectserver/server',
            'assertionConsumerService': {
                'url': 'https://siam1.test.anoigo.nl/aselectserver/server/saml20_assertion_digid'
            }
        }
    })
    art_resp = ArtifactResponse.from_string(get_settings(), art_resp_resource, digid_provider, insecure=True)
    art_resp.raise_for_status()
    assert art_resp.get_bsn() == 's00000000:900029365'
    assert art_resp.provider.saml_spec_version == Version("3.5")


def test_etree_parse_fail():
    test_xml_parse_decl = """<?xml version="1.0" encoding="UTF-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        </soapenv:Body>
    </soapenv:Envelope>
    """

    test_xml_parse_no_decl = """
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        </soapenv:Body>
    </soapenv:Envelope>
    """

    with pytest.raises(ValueError) as exc_info:
        etree.fromstring(test_xml_parse_decl)

    assert exc_info.value.args[0] == "Unicode strings with encoding declaration are not supported. Please use bytes input or XML fragments without declaration."

    # Split works with decleration
    assert etree.fromstring(test_xml_parse_decl.rsplit('<?xml version="1.0" encoding="UTF-8"?>', maxsplit=1)[-1]) is not None

    # Split works without decleration
    nodecl_tree_splitted = etree.fromstring(test_xml_parse_no_decl.rsplit('<?xml version="1.0" encoding="UTF-8"?>', maxsplit=1)[-1])
    nodecl_tree = etree.fromstring(test_xml_parse_no_decl)
    assert nodecl_tree_splitted.tag == nodecl_tree.tag
    assert nodecl_tree_splitted.text == nodecl_tree.text
    assert nodecl_tree_splitted.tail == nodecl_tree.tail
    assert nodecl_tree_splitted.attrib == nodecl_tree.attrib
    assert len(nodecl_tree_splitted) == len(nodecl_tree)


@freeze_time("2021-08-17T14:05:29Z")
def test_artifact_response_output_parseable(mocker, digid_provider_settings, jinja_env):
    with open('tests/resources/artifact_response_digid.xml', 'r', encoding='utf-8') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    digid_provider = IdProvider(get_settings(), 'digid', digid_provider_settings, jinja_env)
    mocker.patch.dict(digid_provider.settings_dict, {
        'sp': {
            'entityId': 'https://siam1.test.anoigo.nl/aselectserver/server',
            'assertionConsumerService': {
                'url': 'https://siam1.test.anoigo.nl/aselectserver/server/saml20_assertion_digid'
            }
        }
    })
    art_resp = ArtifactResponse.from_string(get_settings(), art_resp_resource, digid_provider, insecure=True)
    art_resp_reloaded = ArtifactResponse.from_string(get_settings(), art_resp.to_envelope_string(), digid_provider, insecure=True)

    assert art_resp.issuer.text == art_resp_reloaded.issuer.text
    assert art_resp.response_issuer.text == art_resp_reloaded.response_issuer.text
    assert art_resp.status == art_resp_reloaded.status
