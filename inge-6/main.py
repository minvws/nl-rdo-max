import os.path
import logging

from urllib.parse import urlparse

from redis import ResponseError

from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI, Request, HTTPException, status

from .service.tvs_access import TVSRequestHandler
from .service.cache.redis_cache import redis_cache_service
from .config import settings

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="example")

tvs_request_handler = TVSRequestHandler()

@app.get('/login')
def index(request: Request):
    return tvs_request_handler.login(request=request)

@app.get('/acs')
def acs(request: Request):
    return tvs_request_handler.acs(request=request)

@app.get('/attrs/')
def attrs(request: Request):
    return tvs_request_handler.attrs(request=request)

@app.get('/metadata/')
def metadata(request: Request):
    return tvs_request_handler.metadata(request=request)

@app.get("/")
def read_root(request: Request):
    url_data = urlparse(request.url._url)
    return {
        "headers": request.headers,
        "query_params": request.query_params,
        "path_params": request.path_params,
        "url": url_data.hostname,
    }

@app.get("/heartbeat")
def heartbeat():
    errors = list()

    # Check reachability redis
    if not redis_cache_service.redis_client.ping():
        errors.append("CANNOT REACH REDIS CLIENT ON {}:{}".format(settings.redis_host, settings.redis_port))

    # Check accessability cert and key path
    if not os.access(settings.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML CERT FILE")

    if not os.access(settings.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML KEY FILE")

    if len(errors) != 0:
        raise HTTPException(status_code=500, detail=',\n'.join(errors))

    return

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
