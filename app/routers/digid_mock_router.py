from dependency_injector.wiring import inject
from fastapi import APIRouter, Depends, Request

from app.models.digid_mock_requests import DigiDMockRequest, DigiDMockCatchRequest
from app.providers.digid_mock_provider import DigidMockProvider

digid_mock_router = APIRouter()


@digid_mock_router.post("/digid-mock")
def digid_mock(
    request: Request,
    digid_mock_request: DigiDMockRequest = Depends(DigiDMockRequest.from_request),
):
    return DigidMockProvider.digid_mock(request, digid_mock_request)


@digid_mock_router.get("/digid-mock-catch")
@inject
def digid_mock_catch(digid_mock_catch_request: DigiDMockCatchRequest = Depends()):
    return DigidMockProvider.digid_mock_catch(digid_mock_catch_request)
