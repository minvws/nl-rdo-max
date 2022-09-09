import requests
import urllib.parse


def authorize_request(
    base,
    client_id="test_client",
    redirect_uri="http://localhost:3000/login",
    response_type="code",
    nonce="ZUzmN6qYg6fUgN83sk2Ho7Vfavtsmvann8FutIb3N8s",
    state="Umi-dwDB1En0uhtN2ioluR-RtzZMMV9vRWGMg51Q12I",
    code_challenge="gqo-DaxizFWmd2dxMBH6KExOWFKSLLGOGDTrY-zkJFY",
    code_challenge_method="S256",
    scope="openid",
):
    return requests.get(
        f"{base}/authorize?"
        + urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "nonce": nonce,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "scope": scope,
                "force_digid": "True",
            },
            safe="",
        )
    )


def test__openid_configuration(max_application):
    response = requests.get(f"{max_application}/.well-known/openid-configuration")
    assert response.status_code == 200


def test_authorize_client_id_not_known(max_application):
    response = authorize_request(base=max_application, client_id="bla")
    assert response.json() == {"error": "Client ID not known"}
    assert response.status_code == 400


def test_authorize_redirect_uri_not_known(max_application):
    response = authorize_request(
        base=max_application, redirect_uri="http://localghost:1111"
    )
    assert response.json() == {"error": "Redirect URI not known"}
    assert response.status_code == 400


def test_happy_path(max_application):
    response = authorize_request(base=max_application)
    html_response = response.text.splitlines()
    form_action = html_response[2]
    form_action = form_action[
        form_action.index("digid-mock") + 11 : form_action.index(">") - 1
    ]
    form_action = urllib.parse.parse_qs(form_action)
    assert form_action["idp_name"][0] == "tvs"
    assert len(form_action["state"][0]) == 64
    # Base64 encoded oidc authorize request
    assert (
        form_action["authorize_request"][0]
        == "eyJjbGllbnRfaWQiOiAidGVzdF9jbGllbnQiLCAicmVkaXJlY3RfdXJpIjogImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC9sb2dpbiIsICJyZXNwb25zZV90eXBlIjogImNvZGUiLCAibm9uY2UiOiAiWlV6bU42cVlnNmZVZ044M3NrMkhvN1ZmYXZ0c212YW5uOEZ1dEliM044cyIsICJzY29wZSI6ICJvcGVuaWQiLCAic3RhdGUiOiAiVW1pLWR3REIxRW4wdWh0TjJpb2x1Ui1SdHpaTU1WOXZSV0dNZzUxUTEySSIsICJjb2RlX2NoYWxsZW5nZSI6ICJncW8tRGF4aXpGV21kMmR4TUJINktFeE9XRktTTExHT0dEVHJZLXprSkZZIiwgImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6ICJTMjU2IiwgImF1dGhvcml6YXRpb25fYnlfcHJveHkiOiBmYWxzZX0="
    )
    assert response.status_code == 200
