# System summary
 Inge6 is build as a bridge between the CoronaCheck app and TVS (Toegang Verlenings Service) or DigiD. It allows a end-user to login into digid and provide the app with a token, which can be used to retrieve the BSN of that same end-user. This BSN is used in inge4 to retrieve the related vaccination and test data from the existing provider.

# Dependency:
Forked repo: https://github.com/maxxiefjv/pyop/tree/feature/allow-redis-tls

# Setup

As Inge6 is a OIDC <-> SAML bridge, one has to have files for both. Each file is described below. Further, one needs to create an `inge6.conf` to define all settings. An example is found in inge6.conf.example with the corresponding explanations

## OIDC
For the Open ID Connect protocol we need a file containing the allowed clients. These clients are defined in the `clients_file` setting in the settings file. An example of such a file is found under `clients.json.example`. Finally, one needs to setup a public-private keypair for signing and verification of JWT tokens. Both locations configurable in the settings file.

In short, setup these files:
- `clients_file`, location configurable in the settings.
- `rsa_private key`, for JWT token signing. Location configurable in the settings
- `rsa_public_key`, for JWT token verifcation. Location configurable in the settings

## SAML
SAML handles the communication between Inge6 and the IdP, short for Identity Provider, which is either TVS or DigiD. To make this work we need to setup the SAML directory.

In the configured `identity_provider_settings` file, please make sure that these files are available for each IdP, and reference to the correct IdP files:
- `cert_path`, the certificate used for verifying our signed message. Passed along in requests
- `key_path`, the key used for signing SAML requests
- `settings_path`, a file containing the SAML settings for creating our metadata and requests, and parsing the IdP metadata. An example is provided in saml/settings-dist.json, this file also includes an explanation of the options.
- `idp_metadata_path`, the location of the metadata of the IdP

**note: each idp configured idp is expected to have a subdomain to the configured issuer (with TLS support).**

Template files (these are included in the repository):
- `sp_template`, saml/templates/xml/sp_metadata.xml
- `authn_request_template`, saml/templates/xml/authn_request.xml
- `artifactresolve_request_template`, saml/templates/xml/artifactresolve_request.xml
- `authn_request_html_template`, saml/templates/html/authn_request.html

## Redis
Redis is the store of this service. It is used to temporarily store data acquired during the BSN retrieval process. A redis-server should be setup, and the configuration should be copied in the settings file under the `redis` header.

Further redis expects the keys configured in the config to have a valid value. The keys expected to be set are defined in the config under the following names:
- `primary_idp_key`
- `user_limit_key` (if there is an user limit to be handled by the ratelimiter)

To enable ratelimit overflow, the extra keys are expected to be set. The names of these keys are defined in the config under the following config names:
- `overflow_idp_key`
- `user_limit_key_overflow_idp` (if there is an user limit on the overflow idp to be handled by the ratelimiter)

## SSL (local development)
An SSL connection is usually required, also in an development environment. To set this up, please define where to find the certificates and keys in the settings file under the `ssl` header.

# Running the service
Make sure you followed the steps for the regular Setup, then run:
```bash
$ make setup
...
$ sh run_server.sh
```

# Using the ratelimiter
To activate an overflow IDP, secundairy IDP when primary is too busy, the following settings should be configured in the inge6.conf settings.
- overflow_idp_key, this is the key in the redis store used to retrieve the secundairy IDP name.
- user_limit_key_overflow_idp, (OPTIONAL) if the overflow idp needs an user limit, this key is used to retrieve the user limit from the redis store.

# Contributions
When contributing to inge6 a few Make commands should be considered to make sure linting, type-checking (MyPy) and tests are still valid:
- `make lint`, check linting using pylint.
- `make check-type`, check that typing is done correctly. Also, see 'MyPy: stubs'.
- `make test`, run the tests

or 
- `make check-all`, to check all the above


## MyPy: stubs
To make use of our custom stubs when running mypy make sure you have correctly exported the env variable:
```bash
$ export MYPYPATH=~/work/myproject/stubs
```


# Using the mock environment
For development purposes we have created a 'backdoor' to retrieve a JWT Token for arbitrary BSNs, only available when `mock_digid` is True in the settings file. This setting enables two things:
1. The program flow is altered. By default we do not connect to the actual IdP, instead an 'end-user' is allowed to input an arbitrary BSN and retrieve a corresponding token. However, it still allows for connecting to the actual IdP if that is requested.
2. An additional endpoint is available `/consume_bsn`. This endpoint allows external tools and test services to let Inge6 consume a bsn and return a 'code'. This code can then be used in the `accesstoken_endpoint`, the accesstoken endpoint defined in the settings file, to retrieve a JWT token that corresponds to the provided bsn.

A code example on the second case:
```python
import json
import urllib.parse
import requests

from fastapi.responses import JSONResponse

inge6_mock_uri = "development.inge6.uri/"
redirect_uri = "some.allowlisted.uri"

authorize_params = {
    'client_id': "test_client",
    'redirect_uri': redirect_uri,
    'response_type': "code",
    'nonce': "n-0S6_WzA2Mj",
    'state': "af0ifjsldkj",
    'scope': "openid",
    'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
    'code_challenge_method': "S256",
}

query_params: str = urllib.parse.urlencode(authorize_params)
bsn: str = '999991772'
resp: JSONResponse = requests.get(f'{inge6_mock_uri}/consume_bsn/{bsn}?{query_params}')
if (resp.status_code != 200):
    print('failed consume_bsn request: ', resp.status_code, resp.reason)

code = json.loads(resp.content.decode())['code'][0]
code_verifier = 'SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c'
acc_req_body = f'client_id=test_client&redirect_uri={redirect_uri}&code={code}&code_verifier={code_verifier}&grant_type=authorization_code'

accesstoken_resp: JSONResponse = requests.post(f'{inge6_mock_uri}/accesstoken', acc_req_body)
if (resp.status_code != 200):
    print('failed accesstoken request: ', resp.status_code, resp.body)

accesstoken = json.loads(accesstoken_resp.content.decode())
```

