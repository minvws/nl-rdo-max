from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Depends, Request

from app.providers.signing_provider import SigningProvider

signing_router = APIRouter()


@signing_router.get("/signing")
@inject
def assertion_consumer_service(
        validation_token: str,
        request: Request,
        signing_provider: SigningProvider = Depends(Provide["services.signing_provider"]),
):
    return signing_provider.fetch_signing_jwt(
        request, validation_token
    )
