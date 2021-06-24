import os.path
import logging

import uvicorn

from fastapi import FastAPI

from .config import settings
from .router import router
from .provider import get_provider

app = FastAPI(docs_url= None, redoc_url= None)

app.include_router(router)


def validate_startup():
    if not os.path.isfile(settings.saml.cert_path):
        raise FileNotFoundError("File {} not found. Required for startup".format(settings.saml.cert_path))

    if not os.path.isfile(settings.saml.key_path):
        raise FileNotFoundError("File {} not found. Required for startup".format(settings.saml.key_path))


@app.on_event("startup")
async def startup_event():
    logging.basicConfig(
        level=logging.DEBUG,
        datefmt='%m/%d/%Y %I:%M:%S %p'
    )
    validate_startup()
    get_provider(app)

if __name__ == "__main__":
    run_kwargs = {
        'host': settings.host,
        'port': int(settings.port),
        'reload': settings.debug == "True",
        'proxy_headers': True
    }

    if hasattr(settings, 'use_ssl') and settings.use_ssl.lower() == 'true':
        run_kwargs['ssl_keyfile'] = settings.ssl.base_dir + '/' + settings.ssl.key_file
        run_kwargs['ssl_certfile'] = settings.ssl.base_dir + '/' + settings.ssl.cert_file

    uvicorn.run(
                'inge6.main:app',
                **run_kwargs
            )
