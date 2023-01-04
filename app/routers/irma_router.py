from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Request, Depends

from app.models.irma_disclosure_request import IRMADisclosureRequest
from app.providers.irma_provider import IRMAProvider

irma_router = APIRouter()


@irma_router.post("/irma/disclosure")
@inject
async def disclosure(
        request: Request,
        irma_disclosure_request: IRMADisclosureRequest,
        irma_provider: IRMAProvider = Depends(Provide["services.irma_provider"]),
):
    return irma_provider.disclosure(request.headers, irma_disclosure_request)


@irma_router.get("/irma/session")
@inject
async def session(
        state: str,
        irma_provider: IRMAProvider = Depends(Provide["services.irma_provider"]),
):
    return irma_provider.session_state(state)
