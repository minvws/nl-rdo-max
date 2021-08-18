from inge6.config import Settings

TEST_CONFIG = """
[DEFAULT]
app_name = "CoronaCheck TVS - Digid login"
[ratelimit]
base_dir = ratee
[bsn]
boo = bsn
[ssl]
far = ssl
[oidc]
boofar = oidc
[saml]
foobar = saml
[redis]
barfoo = redis
"""

def test_settings():
    settings: Settings = Settings()
    settings.read_string(TEST_CONFIG)

    assert settings.saml.foobar == 'saml'
    settings.saml.foobar = 'doo'
    assert settings.saml.foobar == 'doo'
