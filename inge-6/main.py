import os.path
import json
import logging

import uvicorn

from starlette.middleware.sessions import SessionMiddleware

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from jwkest.jwk import RSAKey, rsa_load

from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

from .config import settings
from .router import router

# origins = [
#     ""
# ]

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="example")
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

app.include_router(router)

def init_oidc_provider(appw):
    issuer = "https://10.48.118.250:8006" # TODO: !!!
    authentication_endpoint = app.url_path_for('authorize')
    jwks_uri = app.url_path_for('jwks_uri')
    token_endpoint = app.url_path_for('token_endpoint')
    userinfo_endpoint = app.url_path_for('userinfo_endpoint')

    configuration_information = {
        'issuer': issuer,
        'authorization_endpoint': issuer + authentication_endpoint,
        'jwks_uri': issuer + jwks_uri,
        'token_endpoint': issuer + token_endpoint,
        'userinfo_endpoint': issuer + userinfo_endpoint,
        'scopes_supported': ['openid', 'profile'],
        'response_types_supported': ['code', 'code id_token', 'code token', 'code id_token token'],  # code and hybrid
        'response_modes_supported': ['query', 'fragment'],
        'grant_types_supported': ['authorization_code', 'implicit'],
        'subject_types_supported': ['pairwise'],
        'token_endpoint_auth_methods_supported': ['none'],
        'claims_parameter_supported': True
    }

    userinfo_db = Userinfo(app.users)
    with open(settings.oidc.clients_file) as clients_file:
        clients = json.load(clients_file)
    signing_key = RSAKey(key=rsa_load(settings.oidc.rsa_private_key), alg='RS256', )
    provider = Provider(signing_key, configuration_information,
                        AuthorizationState(HashBasedSubjectIdentifierFactory(settings.oidc.subject_id_hash_salt)),
                        clients, userinfo_db)

    return provider


def validate_startup():
    if not os.path.isfile(settings.saml.cert_path):
        raise FileNotFoundError("File {} not found. Required for startup".format(settings.saml.cert_path))

    if not os.path.isfile(settings.saml.key_path):
        raise FileNotFoundError("File {} not found. Required for startup".format(settings.saml.key_path))

@app.on_event("startup")
async def startup_event():
    logging.basicConfig(
        level=logging.DEBUG,
        # format='%(asctime)s %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p'
    )
    validate_startup()

    app.users = {'test_user': {'name': 'Testing Name'}}
    app.provider = init_oidc_provider(app)
    app.logger = logging.getLogger(__package__)


if __name__ == "__main__":
    run_kwargs = {
        'host': settings.host,
        'port': int(settings.port),
        'reload': settings.debug == "True",
    }

    if hasattr(settings, 'use_ssl') and settings.use_ssl.lower() == 'true':
        run_kwargs['ssl_keyfile'] = settings.ssl.base_dir + '/' + settings.ssl.key_file,
        run_kwargs['ssl_certfile'] = settings.ssl.base_dir + '/' + settings.ssl.cert_file

    uvicorn.run(
                'inge-6.main:app',
                **run_kwargs
            )
