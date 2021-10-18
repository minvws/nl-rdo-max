import sys
import json

import os.path
import logging

import uvicorn

from fastapi import FastAPI, Request

from .config import get_settings
from .router import router
from .provider import Provider

log = logging.getLogger(__package__)

app = FastAPI(docs_url= None, redoc_url= None, openapi_url=None)
app.include_router(router)

def _validate_saml_identity_provider_settings():
    missing_files = []
    with open(get_settings().saml.identity_provider_settings, encoding='utf-8') as providers_settings:
        identity_providers = json.loads(providers_settings.read())

    for provider, p_settings in identity_providers.items():
        if not os.path.isdir(p_settings['base_dir']):
            missing_files.append(
                (p_settings['base_dir'], f"{provider}: SAML Identity Providers base directory")
            )

        if not os.path.isfile(p_settings['cert_path']):
            missing_files.append(
                (p_settings['cert_path'], f"{provider}: SAML ID Provider certificate file")
            )

        if not os.path.isfile(p_settings['key_path']):
            missing_files.append(
                (p_settings['key_path'], f"{provider}: SAML ID Provider private key file")
            )

        if not os.path.isfile(p_settings['settings_path']):
            missing_files.append(
                (p_settings['settings_path'], f"{provider}: SAML ID Provider settings file")
            )

        if not os.path.isfile(p_settings['idp_metadata_path']):
            missing_files.append(
                (p_settings['idp_metadata_path'], f"{provider}: SAML ID Provider metadata file")
            )

    return missing_files

def validate_settings(section, keys):
    required_settings = []
    current_settings = getattr(get_settings(), section)
    for key in keys:
        if not hasattr(current_settings, key) or getattr(current_settings, key) == "":
            required_settings.append(
                (f'{section}.{key}', f'expected to be defined in the config {section} section')
            )

    return required_settings

def validate_startup():
    missing_files = []
    ssl_missing_files = []
    required_settings = []

    if not hasattr(get_settings(), 'primary_idp_key') or get_settings().primary_idp_key == "":
        required_settings.append(
            ('settings.primary_idp_key', "expected to be defined in the config DEFAULT section")
        )

    if not os.path.isfile(get_settings().saml.identity_provider_settings):
        missing_files.append(
            (get_settings().saml.identity_provider_settings, "SAML Identity Providers file")
        )
    else:
        missing_files.extend(_validate_saml_identity_provider_settings())

    if not os.path.isfile(get_settings().oidc.clients_file):
        missing_files.append(
            (get_settings().oidc.clients_file, "OIDC clients file")
        )

    if not os.path.isfile(get_settings().oidc.rsa_private_key):
        missing_files.append(
            (get_settings().oidc.rsa_private_key, "OIDC private key file path")
        )

    if not os.path.isfile(get_settings().oidc.rsa_public_key):
        missing_files.append(
            (get_settings().oidc.rsa_private_key, "OIDC public key file path")
        )

    if get_settings().use_ssl.lower() == 'true':
        if not os.path.isdir(get_settings().ssl.base_dir):
            ssl_missing_files.append(
                (get_settings().ssl.base_dir, "SSL base_dir does not exist")
            )

        if not os.path.isfile(get_settings().ssl.base_dir + '/' + get_settings().ssl.cert_file):
            ssl_missing_files.append(
                (get_settings().ssl.cert_file, "SSL certificate file")
            )

        if not os.path.isfile(get_settings().ssl.base_dir + '/' + get_settings().ssl.key_file):
            ssl_missing_files.append(
                (get_settings().ssl.key_file, "SSL key file")
            )

    required_settings += validate_settings("redis", [
            "host",
            "port",
            "enable_debugger",
            "object_ttl",
            "default_cache_namespace",
            "code_namespace",
            "token_namespace",
            "refresh_token_namespace",
            "sub_id_namespace"
        ])

    if not isinstance(get_settings().redis.enable_debugger, bool):
        required_settings.append(
            ('redis.enable_debugger', 'is incorrectly defined, must be True or False')
        )

    if not isinstance(get_settings().redis.ssl, bool):
        required_settings.append(
            ('redis.ssl', 'is incorrectly defined, must be True or False')
        )

    if get_settings().redis.ssl:
        # Check if ssl settings are defined
        required_settings += validate_settings("redis", [
                "ssl",
                "key",
                "cert",
                "cafile"
            ])

        # Check if ssl certs exist on disk
        for key in ['key', 'cert', 'cafile']:
            if not os.path.exists(getattr(get_settings().redis, key)):
                required_settings.append(
                    (f'redis.{key}', 'does not exist on disk')
                )

    error_msg = ""
    if len(missing_files) > 0 or len(ssl_missing_files) > 0:
        missing_files.extend(ssl_missing_files)

        error_msg += "There seem to be missing files, please check these paths:\n\n{}.\n\n".format("\n".join(f"{file[0]}\t\t{file[1]}" for file in missing_files)) # pylint: disable=consider-using-f-string

        if len(ssl_missing_files) > 0:
            error_msg += """
Some of these files seem to be ssl related.
If you didn't mean to enable ssl change this setting in your config (not recommended).
            """

    if len(required_settings) > 0:
        error_msg += "\n\nSome of the required settings seem to be missing, please have a look at:\n\n{}.\n\n".format("\n".join(f"{file[0]}\t\t{file[1]}" for file in required_settings)) # pylint: disable=consider-using-f-string

    if len(missing_files) > 0 or len(ssl_missing_files) > 0 or len(required_settings) > 0:
        log.error(error_msg)
        return False

    return True

@app.on_event("startup")
async def startup_event():
    pass

@app.middleware('http')
async def add_provider_to_request(request: Request, call_next):
    provider = Provider()
    request.app.state.provider = provider
    return await call_next(request)

def main(app_link: str = 'inge6.main:app'):
    settings = get_settings()

    logging.basicConfig(
        level=getattr(logging, settings.loglevel.upper()),
        datefmt='%m/%d/%Y %I:%M:%S %p'
    )

    if not validate_startup():
        sys.exit(1)

    run_kwargs = {
        'host': settings.host,
        'port': int(settings.port),
        'reload': settings.debug == "True",
        'proxy_headers': True,
    }

    if hasattr(settings, 'use_ssl') and settings.use_ssl.lower() == 'true':
        run_kwargs['ssl_keyfile'] = settings.ssl.base_dir + '/' + settings.ssl.key_file
        run_kwargs['ssl_certfile'] = settings.ssl.base_dir + '/' + settings.ssl.cert_file

    uvicorn.run(
                app_link,
                **run_kwargs
            )

if __name__ == "__main__":
    main()
