import os
from typing import Optional, List, Dict

import urllib.request
from urllib.parse import urlparse

from starlette.middleware.sessions import SessionMiddleware

from fastapi.encoders import jsonable_encoder
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from . import config

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="example")

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=config.settings.saml_path)
    return auth

# TODO: Convert to fastapi standards.
def prepare_flask_request(request, url_data):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        'https': 'on' if request.url.scheme == 'https' else 'off',
        'http_host': request.client.host,
        'server_port': url_data.port,
        'script_name': url_data.path,
        'get_data': request.query_params,
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.body
    }

@app.get('/login')
def index(request: Request):
    url_data = urlparse(request.url._url)

    req = prepare_flask_request(request, url_data)
    auth = init_saml_auth(req)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False


    if 'sso' in request.query_params:
        # return redirect(auth.login())
        # If AuthNRequest ID need to be stored in order to later validate it, do instead
        sso_built_url = auth.login()
        request.session['AuthNRequestID'] = auth.get_last_request_id()
        return RedirectResponse(sso_built_url)
    elif 'sso2' in request.args:
        return_to = '%sattrs/' % url_data.hostname
        return RedirectResponse(auth.login(return_to))
    # elif 'slo' in request.args:
    #     name_id = request.session.get('samlNameId', None)
    #     session_index = request.session.get('samlSessionIndex', None)
    #     name_id_format = request.session.get('samlNameIdFormat', None)
    #     name_id_nq = request.session.get('samlNameIdNameQualifier', None)
    #     name_id_spnq = request.session.get('samlNameIdSPNameQualifier', None)

    #     return redirect(auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq))
    elif 'acs' in request.args:
        request_id = None
        if 'AuthNRequestID' in session:
            request_id = session['AuthNRequestID']

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        if len(errors) == 0:
            if 'AuthNRequestID' in session:
                del session['AuthNRequestID']
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlNameIdFormat'] = auth.get_nameid_format()
            session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
            session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
    # elif 'sls' in request.args:
    #     request_id = None
    #     if 'LogoutRequestID' in session:
    #         request_id = session['LogoutRequestID']
    #     dscb = lambda: session.clear()
    #     url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
    #     errors = auth.get_errors()
    #     if len(errors) == 0:
    #         if url is not None:
    #             return redirect(url)
    #         else:
    #             success_slo = True
    #     elif auth.get_settings().is_debug_active():
    #         error_reason = auth.get_last_error_reason()

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    raise HTTPException(status_code=404, detail=', '.join(errors))


@app.get('/attrs/')
def attrs(request: Request):
    paint_logout = False
    attributes = False

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    resp = {
        'paint_logout': paint_logout,
        'attributes': attributes
    }

    json_compatible_item_data = jsonable_encoder(resp)
    return JSONResponse(content=json_compatible_item_data)

@app.get('/metadata/')
def metadata(request: Request):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        return Response(content=metadata, media_type="application/xml")

    raise HTTPException(status_code=500, detail=', '.join(errors))


@app.get("/")
def read_root(request: Request):
    url_data = urlparse(request.url._url)
    return {
        "headers": request.headers,
        "query_params": request.query_params,
        "path_params": request.path_params,
        "url": url_data.hostname,
    }

