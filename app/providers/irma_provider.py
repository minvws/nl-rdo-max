from typing import Any, Dict

import requests
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, HTMLResponse
from pyop.provider import Provider as PyopProvider, extract_bearer_token_from_http_request  # type: ignore[attr-defined]
from starlette.datastructures import Headers

from app.exceptions.max_exceptions import UnauthorizedError
from app.misc.utils import file_content_raise_if_none, dict_intersection
from app.models.acs_context import AcsContext
from app.models.irma_disclosure_request import IRMADisclosureRequest
from app.services.encryption.jwe_service import JweService
from app.services.userinfo.userinfo_service import UserinfoService
from app.storage.authentication_cache import AuthenticationCache


class IRMAProvider:

    def __init__(
            self,
            authentication_cache: AuthenticationCache,
            jwe_service: JweService,
            userinfo_service: UserinfoService,
            pyop_provider: PyopProvider,
            clients: Dict[str, Any]
    ):
        self._authentication_cache = authentication_cache
        self._jwe_service = jwe_service
        self._userinfo_service = userinfo_service
        self._clients = clients
        self._pyop_provider = pyop_provider

    def disclosure(self, headers: Headers, irma_disclosure_request: IRMADisclosureRequest):
        bearer_token = extract_bearer_token_from_http_request(
            authz_header=headers.get("Authorization")
        )
        authentication_context = self._authentication_cache.get_userinfo_context(bearer_token)
        client = self._clients[authentication_context.client_id]

        if "client_privatekey_path" not in client:
            raise UnauthorizedError("Client is not authorized to disclose credentials")

        privkey = file_content_raise_if_none(
            self._clients[authentication_context.client_id]["client_privatekey_path"])
        decrypted_disclosure = self._jwe_service.from_jwe(
            authentication_context.userinfo,
            privkey
        )
        return JSONResponse(
            content=jsonable_encoder(self._userinfo_service.irma_disclosure(
                dict_intersection(irma_disclosure_request.disclosure_context, decrypted_disclosure))))

    def session_state(self, state):
        authentication_request_state = self._authentication_cache.get_authentication_request_state(
            state
        )
        irma_session = requests.get(
            f"http://localhost:4544/session/{authentication_request_state.authentication_state['session_token']}/result", # todo: Config!
        ).json()
        resp = {"status": irma_session["status"]}
        if irma_session["status"] == "DONE":
            if len(irma_session["disclosed"]) != 1:
                raise Exception("Invalid credentials disclosed")

            authentication_request = self._authentication_cache.get_authentication_request_state(state)

            auth_req = authentication_request.authorization_request
            if not authentication_request:
                return HTMLResponse(
                    status_code=404, content="Session expired, user not authorized"
                )

            pyop_authorize_response = self._pyop_provider.authorize(  # type:ignore
                auth_req, "client"
            )
            self._authentication_cache.cache_acs_context(
                pyop_authorize_response["code"], AcsContext(
                    client_id=authentication_request.authorization_request["client_id"],
                    authentication_method=authentication_request.authentication_method,
                    context=irma_session["disclosed"][0]
                )
            )
            resp["redirect_url"] = pyop_authorize_response.request(auth_req["redirect_uri"], False)
        return JSONResponse(content=jsonable_encoder(resp))
