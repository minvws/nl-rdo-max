# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
import uuid

from fastapi import Request
from fastapi.responses import RedirectResponse, Response

from app.services.template_service import TemplateService
from app.models.digid_mock_requests import DigiDMockRequest, DigiDMockCatchRequest


class DigidMockProvider:
    def __init__(self, template_service: TemplateService):
        self._template_renderer = template_service.templates

    def digid_mock(
        self, request: Request, digid_mock_request: DigiDMockRequest
    ) -> Response:
        state = digid_mock_request.state
        authorize_request = digid_mock_request.authorize_request
        idp_name = digid_mock_request.idp_name
        relay_state = digid_mock_request.RelayState
        artifact = str(uuid.uuid4())
        return self._template_renderer.TemplateResponse(
            "digid_mock.html",
            {
                "request": request,
                "artifact": artifact,
                "relay_state": relay_state,
                "state": state,
                "idp_name": idp_name,
                "authorize_request": authorize_request,
            },
        )

    def digid_mock_catch(self, request: DigiDMockCatchRequest) -> RedirectResponse:
        bsn = request.bsn
        relay_state = request.RelayState

        response_uri = "acs" + f"?SAMLart={bsn}&RelayState={relay_state}&mocking=1"
        return RedirectResponse(response_uri, status_code=303)
