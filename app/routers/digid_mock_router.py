from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Depends

from app.models.digid_mock_requests import DigiDMockRequest, DigiDMockCatchRequest
from app.models.login_digid_request import LoginDigiDMockRequest
from app.providers.digid_mock_provider import DigidMockProvider

digid_mock_router = APIRouter()


@digid_mock_router.post("/digid-mock")
def digid_mock(
    digid_mock_request: DigiDMockRequest = Depends(DigiDMockRequest.from_request),
):
    return DigidMockProvider.digid_mock(digid_mock_request)


@digid_mock_router.get("/login-digid")
@inject
def login_digid(
    digid_mock_provider: DigidMockProvider = Depends(
        Provide["services.digid_mock_provider"]
    ),
    login_digid_request: LoginDigiDMockRequest = Depends(
        LoginDigiDMockRequest.from_request
    ),
):
    return digid_mock_provider.login_digid(login_digid_request=login_digid_request)


@digid_mock_router.get("/digid-mock-catch")
@inject
def digid_mock_catch(digid_mock_catch_request: DigiDMockCatchRequest = Depends()):
    return DigidMockProvider.digid_mock_catch(digid_mock_catch_request)
