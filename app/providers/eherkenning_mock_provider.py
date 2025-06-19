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
from app.models.eherkenning_mock_requests import (
    EherkenningMockRequest,
    EherkenningMockCatchRequest,
)


class EherkenningMockProvider:
    def __init__(self, template_service: TemplateService):
        self._template_renderer = template_service.templates

    def eherkenning_mock(
        self, request: Request, eherkenning_mock_request: EherkenningMockRequest
    ) -> Response:
        state = eherkenning_mock_request.state
        authorize_request = eherkenning_mock_request.authorize_request
        idp_name = eherkenning_mock_request.idp_name
        relay_state = eherkenning_mock_request.RelayState
        artifact = str(uuid.uuid4())
        return self._template_renderer.TemplateResponse(
            request=request,
            name="eherkenning_mock.html",
            context={
                "artifact": artifact,
                "relay_state": relay_state,
                "state": state,
                "idp_name": idp_name,
                "authorize_request": authorize_request,
            },
        )

    def eherkenning_mock_catch(
        self, request: EherkenningMockCatchRequest
    ) -> RedirectResponse:
        kvk = request.kvk
        relay_state = request.RelayState

        response_uri = "acs" + f"?SAMLart={kvk}&RelayState={relay_state}&mocking=1"
        return RedirectResponse(response_uri, status_code=303)
