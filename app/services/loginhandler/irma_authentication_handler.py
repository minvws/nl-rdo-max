import base64
import json
from typing import Any, Dict

import requests
from fastapi import Request
from fastapi.templating import Jinja2Templates
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.exceptions.max_exceptions import ServerErrorException
from app.misc.utils import file_content_raise_if_none
from app.models.acs_context import AcsContext
from app.models.authorize_request import AuthorizeRequest
# todo this to constant
from app.services.encryption.jwe_service import JweService
from app.services.loginhandler.authentication_handler import AuthenticationHandler

templates = Jinja2Templates(directory="jinja2")
IRMA_PREFIX = "irma-demo.uzipoc-cibg.uzi"


class IrmaAuthenticationHandler(AuthenticationHandler):
    def __init__(
            self,
            jwe_service: JweService,
            clients: Dict[str, Any]
    ):
        self._jwe_service = jwe_service
        self._clients = clients

    def authentication_state(self, authorize_request: AuthorizeRequest) -> Dict[str, Any]:
        client = self._clients[authorize_request.client_id]
        if "disclosure_clients" in client:
            raise ServerErrorException("Disclosure client cannot login with IRMA")
        pload = {
            "@context": "https://irma.app/ld/request/disclosure/v2",
            "disclose": [
                [
                    [
                        {
                            "type": "irma-demo.uzipoc-cibg.uzi.uraName",
                            "value": client["name"],
                        },
                        {
                            "type": "irma-demo.uzipoc-cibg.uzi.uraNumber",
                            "value": client["external_id"],
                        },
                        {"type": "irma-demo.uzipoc-cibg.uzi.uziNumber"},
                        {"type": "irma-demo.uzipoc-cibg.uzi.hasRole01-041"},
                        {"type": "irma-demo.uzipoc-cibg.uzi.hasRole30-000"},
                        {"type": "irma-demo.uzipoc-cibg.uzi.hasRole01-010"},
                        {"type": "irma-demo.uzipoc-cibg.uzi.hasRole01-011"},
                    ]
                ]
            ],
        }
        irma_response = requests.post(
            f"http://localhost:4544/session", #todo: to the config
            headers={"Content-Type": "application/json"},
            data=json.dumps(pload),
        ).json()
        return {
            "session_pointer": irma_response["sessionPtr"],
            "session_token": irma_response["token"]
        }

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
                "qr_code": base64.b64encode(
                    json.dumps(authorize_state["session_pointer"]).encode("utf-8")).decode("utf-8"),
                "session_url": f"/irma/session?state={randstate}"
            }
        )

    def resolve_authentication_artifact(self, acs_context: AcsContext) -> str:
        cibg_disclosure = {"roles": []}
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
            raise ServerErrorException(f'Unable to find client for ura_number {cibg_disclosure["ura_number"]}')
        return self._jwe_service.to_jwe(cibg_disclosure, file_content_raise_if_none(client["client_certificate_path"]))
