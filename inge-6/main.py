from urllib.parse import urlparse

from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI, Request

from .service.tvs_access import TVSRequestHandler

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
