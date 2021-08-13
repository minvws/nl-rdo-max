import pytest
from lxml import etree

import base64, zlib
import urllib.parse as urlparse

from starlette.datastructures import Headers
from fastapi.responses import RedirectResponse

from inge6.models import AuthorizeRequest
from inge6.provider import Provider

from inge6.config import settings

NAMESPACES = {
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
}

def decode_base64_and_inflate( b64string ):
    decoded_data = base64.b64decode( b64string )
    return zlib.decompress( decoded_data , -15)

@pytest.fixture
def provider() -> Provider:
    yield Provider()

# pylint: disable=redefined-outer-name
def test_authorize_endpoint(provider: Provider):
    """
    Test if the generated authn request corresponds with the
    expected values:

    <samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="ONELOGIN_1d940b35a906b780f8574c26fcc4945e8a5d0de9"  Version="2.0"
        IssueInstant="2021-08-13T11:35:43Z"
        AssertionConsumerServiceURL="https://tvs.acc.coronacheck.nl/acs"
        ProviderName="Ministerie van Volksgezondheid, Welzijn en Sport">
        <saml:Issuer>http://sp.example.com</saml:Issuer>
        <samlp:RequestedAuthnContext Comparison="minimum">
            <saml:AuthnContextClassRef>
                urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
            </saml:AuthnContextClassRef>
        </samlp:RequestedAuthnContext>
    </samlp:AuthnRequest>
    """

    auth_req = AuthorizeRequest(
        client_id="test_client",
        redirect_uri="http://localhost:3000/login",
        response_type="code",
        nonce="n-0S6_WzA2Mj",
        state="af0ifjsldkj",
        scope="openid",
        code_challenge="_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier = SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        code_challenge_method="S256",
    )

    headers = Headers()

    resp: RedirectResponse = provider.authorize_endpoint(auth_req, headers, '0.0.0.0')
    redirect_url = resp.headers.get('location')

    parsed_url = urlparse.urlparse(redirect_url)
    query_params = urlparse.parse_qs(parsed_url.query)
    assert all(key in query_params.keys() for key in ['SAMLRequest', 'RelayState', 'Signature', 'SigAlg'])

    generated_authnreq = decode_base64_and_inflate(query_params['SAMLRequest'][0]).decode()
    parsed_authnreq = etree.fromstring(generated_authnreq).getroottree().getroot()

    assert parsed_authnreq.attrib['ID'] is not None
    assert parsed_authnreq.attrib['IssueInstant'] is not None
    assert parsed_authnreq.attrib['AssertionConsumerServiceURL'] is not None
    assert parsed_authnreq.attrib['ProviderName'] is not None
    assert parsed_authnreq.find('./saml:Issuer', NAMESPACES) is not None

    # TODO: What should the issuer contain
    assert parsed_authnreq.find('./saml:Issuer', NAMESPACES).text == settings.issuer
    assert parsed_authnreq.find('./samlp:RequestedAuthnContext', NAMESPACES) is not None
    assert parsed_authnreq.find('.//saml:AuthnContextClassRef', NAMESPACES) is not None
