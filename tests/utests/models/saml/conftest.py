import pytest
from jwcrypto.jwk import JWK

from tests.utils import make_test_rsa_key


@pytest.fixture
def private_key_for_saml_test() -> JWK:
    return make_test_rsa_key()
