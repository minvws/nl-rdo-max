import sys
import os.path
import logging

import uvicorn

from fastapi import FastAPI

from .config import settings
from .router import router
from .provider import get_provider

log = logging.getLogger(__package__)

app = FastAPI(docs_url= None, redoc_url= None, openapi_url=None)
app.include_router(router)


def validate_startup():
    missing_files = []
    ssl_missing_files = []

    if not os.path.isfile(settings.saml.cert_path):
        missing_files.append(
            (settings.saml.cert_path, "SAML certificate file")
        )

    if not os.path.isfile(settings.saml.key_path):
        missing_files.append(
            (settings.saml.key_path, "SAML key file")
        )

    if not os.path.isfile(settings.saml.settings_path):
        missing_files.append(
            (settings.saml.settings_path, "SAML settings file")
        )

    if not os.path.isfile(settings.saml.idp_path):
        missing_files.append(
            (settings.saml.idp_path, "SAML Identity Provider Metadata")
        )

    if not os.path.isfile(settings.oidc.clients_file):
        missing_files.append(
            (settings.oidc.clients_file, "OIDC clients file")
        )

    if not os.path.isfile(settings.oidc.rsa_private_key):
        missing_files.append(
            (settings.oidc.rsa_private_key, "OIDC private key file path")
        )

    if not os.path.isfile(settings.oidc.rsa_public_key):
        missing_files.append(
            (settings.oidc.rsa_private_key, "OIDC public key file path")
        )

    if settings.use_ssl.lower() == 'true':
        if not os.path.isdir(settings.ssl.base_dir):
            ssl_missing_files.append(
                (settings.ssl.base_dir, "SSL base_dir does not exist")
            )

        if not os.path.isfile(settings.ssl.base_dir + '/' + settings.ssl.cert_file):
            ssl_missing_files.append(
                (settings.ssl.cert_file, "SSL certificate file")
            )

        if not os.path.isfile(settings.ssl.base_dir + '/' + settings.ssl.key_file):
            ssl_missing_files.append(
                (settings.ssl.key_file, "SSL key file")
            )


    if len(missing_files) > 0 or len(ssl_missing_files) > 0:
        missing_files.extend(ssl_missing_files)

        error_msg = "There seem to be missing files, please check these paths:\n\n{}.\n\n".format("\n".join(f"{file[0]}\t\t{file[1]}" for file in missing_files))

        if len(ssl_missing_files) > 0:
            error_msg += """
Some of these files seem to be ssl related.
If you didn't mean to enable ssl change this setting in your config (not recommended).
            """

        log.error(error_msg)
        sys.exit(1)

@app.on_event("startup")
async def startup_event():
    get_provider()

if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, settings.loglevel.upper()),
        datefmt='%m/%d/%Y %I:%M:%S %p'
    )
    validate_startup()

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
                'inge6.main:app',
                **run_kwargs
            )
