import pytest

from inge6.saml import ArtifactResponseParser, artifact_response

"""
    We have two test files, one for verifying the signatures and one for validating the decryption.
    The 'artiresp.xml' contains an similar XML structure but with a custom AES key, created after
    reencrypting the original AES key with a custom key. # TODO: create reencrypt command.
    The 'artifact_resonse_ex.xml' is the orignal message as provided on an acceptance environment,
    and can thus be used for signature validation.
"""



# @pytest.mark.skip(reason='no way of currently testing this other than on one machine... :/')
def test_artifact_response_parser_get_bsn():
    with open('tests/resources/artiresp.xml') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    artifact_response = ArtifactResponseParser(art_resp_resource,verify=False)
    assert artifact_response.get_bsn() == '900212640'

def test_artifact_response_parser_verify():
    with open('tests/resources/artifact_response_ex.xml') as resp_ex_f:
        art_resp_resource = resp_ex_f.read()

    ArtifactResponseParser(art_resp_resource)
    assert True
