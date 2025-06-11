from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Depends, Request

from app.models.eherkenning_mock_requests import EherkenningMockRequest, EherkenningMockCatchRequest
from app.providers.eherkenning_mock_provider import EherkenningMockProvider

eherkenning_mock_router = APIRouter()


@eherkenning_mock_router.post("/eherkenning-mock")
@inject
def eherkenning_mock(
    request: Request,
    eherkenning_mock_request: EherkenningMockRequest = Depends(EherkenningMockRequest.from_request),
    eherkenning_mock_provider: EherkenningMockProvider = Depends(
        Provide["services.eherkenning_mock_provider"]
    ),
):
    return eherkenning_mock_provider.eherkenning_mock(request, eherkenning_mock_request)


@eherkenning_mock_router.get("/eherkenning-mock-catch")
@inject
def eherkenning_mock_catch(
    eherkenning_mock_catch_request: EherkenningMockCatchRequest = Depends(),
    eherkenning_mock_provider: EherkenningMockProvider = Depends(
        Provide["services.eherkenning_mock_provider"]
    ),
):
    return eherkenning_mock_provider.eherkenning_mock_catch(eherkenning_mock_catch_request)
