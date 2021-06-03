from inge6.saml import ArtifactResponseParser

def test_artifact_response_parser_get_bsn():
    with open('tests/resources/artiresp.xml') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    assert ArtifactResponseParser(art_resp_resource).get_bsn() == '900212640'
