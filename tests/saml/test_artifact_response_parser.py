# pylint: disable=c-extension-no-member
from datetime import datetime, timedelta

import pytest

from freezegun import freeze_time
from lxml import etree

from inge6.saml import ArtifactResponse
from inge6.saml.id_provider import IdProvider
from inge6.saml.provider import Provider as SAMLProvider
from inge6.saml.exceptions import UserNotAuthenticated
from inge6.saml.constants import NAMESPACES

# pylint: disable=pointless-string-statement
"""
    We have multiple test files in the resources folder, as we are not allowed to communicate with the SAML Provider directly
    we have some edited files with custom keys. This, inherently, means that signature validation will fail on those files.
    For that purpose we have several files, each with its own purpose.

    Specifically for the BSN decryption test, we have reencrypted the AES key with a random keypair of which the private key
    is pasted as a string in the variable `PRIV_KEY_BSN_AES_KEY`.
"""

PRIV_KEY_BSN_AES_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7CPRE3z+Y77T+lCPzH9geTrz9xz7hGX7V31I0Y3BV6TdWk+D
sOFxhVMwRJ22TicJgqK/lz5V4b09gIPDR8MbBRdgN3NOLWZS4XtXeW8ZwOXmLSXX
j3r0f2KNMKwBUYRfDtLMZCLv/Z6VJgAlbenot+b0B86Axyw7S+NRVLPCL2X5dYs3
vQvauAxSdFk4zet0gI4APmdwIf/QXVovZI/lwt6rG6+YT7MAzJY9QTTIUgN/wnrd
muolaBzSl+qj5bQWeUNhIZZwOyAFroJgWUJirUiX/NgQMr5CdKh5TefPB9t/hUfj
nZKSsvSob5qe6lO36P/Wdc2qAhUrIpP+UsiWtwIDAQABAoIBAAIpcciT5GBVZutr
wWVF5UQ23fTtNwBHTr3GT9xbR+HdiIlDIRmFdtyZnl+CciDVCqk/hDGGSJMAgIek
rS0DBERPqnnXfGe+ABRAZNSfx8SUVj8jkY2muoZQCKrhaEGuzI/+LhDcoQXZZdQr
PCx9b7v/SUyo/1TTetd/BUeZPbXhXJ7LO2xCpmee+5K6RlpfD/urT4Qnh/KfNbIv
bNWSObgo6CCOCzjTk1fZhH6h+LizIwZbXdqIeBLBdW8K3Ps11E+usLmDIXB7n9VD
6ymau/S7sSPf1DEin4nxvyahrTAU98NkFwGZ/pY12xhQ/lnlxzXwda49XoyS8eSO
+zhbUcECgYEA9iy76BWrF6Osvn1Em6BYUgB3XqPTAN3S56A/LcqOAVLjNXg7K3bv
e/xL3di3LGQfoQr1vZ8SC2lzSvGP9uIyYhrQ5VrVuqA6lhSdBtjlSDNj/XS4z5AU
DQaMgfPqGnTpHfOZZFlkhhY+ylXl9PmLtnxZEOCERhvyJglL7EbxPcsCgYEA9ZCN
gxIDdwRr3lQoogW3rUgR29vW83e8IiuPelmOJEXm22o1X6znSVNWLCTg3w5gkvx5
FqPQKa+AfTIslfE9pF0qoTyTE6L5x/feVyUZ4K0+QfhZQDlbahg6OAshn1gAGbxp
NShyPE+4uVVmucYPNnOeZpCScLkgQsApcebq7UUCgYBMiawChHolZ2YV86yZFklf
dXWnnxfDdTRVf6Uk/40XLEYoIbGD2f6rdc3As9h/nMGYuGefBQ3/LlICQwiXocw4
ZE3+gTdiRt7wOoh30Ie44wF7lAbBwfH5+sdEwClRAHhaL5rJcGGortHm5r4QZGXj
3tVyQdveUGIBIXLRi10F8QKBgGRdupkRqbzhX701JI5kS9hVFoeH6OkFzS0iJLhb
Fg+ZSmvvkvUR1E5R82yDfi1s0OgCrPMl7RS8mIWTFkoKmakuMxhHi82A1Rp4IrX3
ggYkiMep28C2MLjCQjlZw1o/O3tJWK7TYy1nYBbP4vaXDuywgNNmz5Om9pqRs97M
BMUJAoGBAOBSnu1WbT6JZC9a6bBfAdySg1muVC9Kn3ENznKboO6YjPE9Joiv3nYB
uVMYjWfxR/Ub1uu5XcVrxGHKpmpTrRMvYOJwexlJQlc7p1aSZ0ttxgvewfUcxJrc
PMn2xczoZzs7FpuIdsN62kxrd+bAPhC25K9mwG3oPZxR+aITjEKD
-----END RSA PRIVATE KEY-----"""

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
    return SAMLProvider()

@freeze_time("2021-06-01 12:44:06")
# pylint: disable=redefined-outer-name
def test_get_bsn_tvs(response_custom_bsn_tvs, monkeypatch, tvs_provider_settings):
    tvs_provider = IdProvider('tvs', tvs_provider_settings)
    artifact_response = ArtifactResponse.from_string(response_custom_bsn_tvs, tvs_provider, insecure=True)

    monkeypatch.setattr(tvs_provider, 'priv_key', PRIV_KEY_BSN_AES_KEY)
    assert artifact_response.get_bsn() == '900212640'

@freeze_time("2021-08-18 16:35:24.335248")
# pylint: disable=redefined-outer-name
def test_from_string_tvs(response_unedited_tvs, tvs_provider_settings):
    tvs_provider = IdProvider('tvs', tvs_provider_settings)
    ArtifactResponse.from_string(response_unedited_tvs, tvs_provider, is_test_instance=True)
    assert True

# pylint: disable=redefined-outer-name
@freeze_time("2021-06-06 11:40:11")
def test_authnfailed_tvs(response_authn_failed_tvs, tvs_provider_settings):
    tvs_provider = IdProvider('tvs', tvs_provider_settings)
    with pytest.raises(UserNotAuthenticated):
        ArtifactResponse.from_string(response_authn_failed_tvs, tvs_provider, insecure=True).raise_for_status()


@freeze_time("2021-08-17T14:05:29Z")
def test_artifact_response_parse_digid(mocker, digid_provider_settings):
    with open('tests/resources/artifact_response_digid.xml', 'r', encoding='utf-8') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    digid_provider = IdProvider('digid', digid_provider_settings)
    mocker.patch.dict(digid_provider.settings_dict, {
        'sp': {
            'entityId': 'https://siam1.test.anoigo.nl/aselectserver/server',
            'assertionConsumerService': {
                'url': 'https://siam1.test.anoigo.nl/aselectserver/server/saml20_assertion_digid'
            }
        }
    })
    art_resp = ArtifactResponse.from_string(art_resp_resource, digid_provider, insecure=True)
    art_resp.raise_for_status()
    assert art_resp.get_bsn() == 's00000000:900029365'
    assert art_resp.provider.saml_spec_version == 3.5


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
