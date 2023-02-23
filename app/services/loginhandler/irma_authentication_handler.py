import base64
import json
from typing import Any, Dict

from fastapi import Request
from fastapi.templating import Jinja2Templates
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.exceptions.max_exceptions import ServerErrorException, InvalidClientException
from app.misc.utils import file_content_raise_if_none
from app.models.acs_context import AcsContext
from app.models.authorize_request import AuthorizeRequest
# todo this to constant
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.loginhandler.authentication_handler import AuthenticationHandler

templates = Jinja2Templates(directory="jinja2")
IRMA_PREFIX = "irma-demo.uzipoc-cibg.uzi"


class IrmaAuthenticationHandler(AuthenticationHandler):
    def __init__(
        self,
        jwe_service_provider: JweServiceProvider,
        clients: Dict[str, Any]
    ):
        self._jwe_service_provider = jwe_service_provider
        self._clients = clients

    def authentication_state(self, authorize_request: AuthorizeRequest) -> Dict[str, Any]:
        client = self._clients[authorize_request.client_id]
        if "disclosure_clients" in client:
            return {"irma_context": {
                    "@context": "https://irma.app/ld/request/disclosure/v2",
                    "disclose": [
                        [
                            [
                                {"type": "irma-demo.uzipoc-cibg.uzi-2.uziId"},
                            ]
                        ]
                    ],
                }}
        return {"irma_context":
                {
                    "@context": "https://irma.app/ld/request/disclosure/v2",
                    "disclose": [
                        [
                            [
                                {
                                    "type": "irma-demo.uzipoc-cibg.uzi-2.entityName",
                                    "value": client["name"],
                                },
                                {
                                    "type": "irma-demo.uzipoc-cibg.uzi-2.ura",
                                    "value": client["external_id"],
                                },
                                {"type": "irma-demo.uzipoc-cibg.uzi-2.uziId"},
                                {"type": "irma-demo.uzipoc-cibg.uzi-2.roles"}
                            ]
                        ]
                    ],
                }}

    def authorize_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        pyop_authentication_request: AuthorizationRequest,
        authorize_state: Dict[str, Any],
        randstate: str,
    ) -> Response:
        return templates.TemplateResponse(
            "irma_authorize.html",
            {
                "request": request,
                "session_url": f"/irma/session?state={randstate}",
                "state": randstate
            }
        )

    def resolve_authentication_artifact(self, acs_context: AcsContext) -> str:
        cibg_disclosure = {"roles": []}
        print(acs_context)
        disclosed = acs_context.context
        for item in disclosed:
            if item["id"] == f"{IRMA_PREFIX}.uraName":
                cibg_disclosure["ura_name"] = item['rawvalue']
            elif item["id"] == f"{IRMA_PREFIX}.uraNumber":
                cibg_disclosure["ura_number"] = item['rawvalue']
            elif item["id"] == f"{IRMA_PREFIX}.uziNumber":
                cibg_disclosure["uzi_number"] = item['rawvalue']
            elif item["id"].startswith(f"{IRMA_PREFIX}.hasRole"):
                if item["rawvalue"] == "yes":
                    role = item["id"][len(IRMA_PREFIX) + 1:]
                    role.replace("-", ".")
                    cibg_disclosure["roles"].append(role)
        client = None
        for client_id in self._clients:
            if self._clients[client_id]["external_id"] == cibg_disclosure["ura_number"]:
                client = self._clients[client_id]
                break
        if client is None:
            raise ServerErrorException(
                error_description=f'Unable to find client for ura_number {cibg_disclosure["ura_number"]}')
        jwe_service = self._jwe_service_provider.get_jwe_service(client["pubkey_type"])
        return jwe_service.to_jwe(cibg_disclosure, file_content_raise_if_none(client["client_certificate_path"]))
