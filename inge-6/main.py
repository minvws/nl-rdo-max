import os.path
import logging

from starlette.middleware.sessions import SessionMiddleware

from fastapi import FastAPI
from jwkest.jwk import RSAKey, rsa_load

from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

from .config import settings
from .router import router

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="example")
app.include_router(router)

def init_oidc_provider(appw):
    issuer = "https://localhost:8006" # TODO: !!!
    authentication_endpoint = app.url_path_for('authentication_endpoint')
    jwks_uri = app.url_path_for('jwks_uri')
    token_endpoint = app.url_path_for('token_endpoint')
    userinfo_endpoint = app.url_path_for('userinfo_endpoint')

    configuration_information = {
        'issuer': issuer,
        'authorization_endpoint': authentication_endpoint,
        'jwks_uri': jwks_uri,
        'token_endpoint': token_endpoint,
        'userinfo_endpoint': userinfo_endpoint,
        'scopes_supported': ['openid', 'profile'],
        'response_types_supported': ['code', 'code id_token', 'code token', 'code id_token token'],  # code and hybrid
        'response_modes_supported': ['query', 'fragment'],
        'grant_types_supported': ['authorization_code', 'implicit'],
        'subject_types_supported': ['pairwise'],
        'token_endpoint_auth_methods_supported': ['client_secret_basic'],
        'claims_parameter_supported': True
    }

    userinfo_db = Userinfo([])
    signing_key = RSAKey(key=rsa_load('secrets/private_unencrypted.pem'), alg='RS256', )
    provider = Provider(signing_key, configuration_information,
                        AuthorizationState(HashBasedSubjectIdentifierFactory(settings.SUBJECT_ID_HASH_SALT)),
                        {}, userinfo_db)

    return provider


def validate_startup():
    if not os.path.isfile(settings.cert_path):
        raise FileNotFoundError("File {} not found. Required for startup".format(settings.cert_path))

    if not os.path.isfile(settings.key_path):
        raise FileNotFoundError("File {} not found. Required for startup".format(settings.key_path))

@app.on_event("startup")
async def startup_event():
    logging.basicConfig(
        level=logging.DEBUG,
        # format='%(asctime)s %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p'
    )

    validate_startup()

    app.provider = init_oidc_provider(app)
    app.logger = logging.getLogger(__package__)
