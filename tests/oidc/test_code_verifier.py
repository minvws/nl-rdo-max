from inge6.oidc.authorize import verify_code_verifier

def test_code_verifier():
    cc_cm = {
        "code_challenge": "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw",
        "code_challenge_method": "S256"
    }

    code_verifier = "SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c"

    assert verify_code_verifier(cc_cm, code_verifier)


def test_padded_code_challenge():
    cc_cm = {
        "code_challenge": "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw=",
        "code_challenge_method": "S256"
    }

    code_verifier = "SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c"

    assert not verify_code_verifier(cc_cm, code_verifier)


def test_plaintext_code_challenge():
    cc_cm = {
        "code_challenge": "SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c",
        "code_challenge_method": "plain"
    }

    code_verifier = "SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c"

    assert not verify_code_verifier(cc_cm, code_verifier)
