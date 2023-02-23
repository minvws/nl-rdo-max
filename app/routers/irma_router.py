from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Depends

from app.providers.irma_provider import IRMAProvider

irma_router = APIRouter()


@irma_router.post("/irma/session")
@inject
def irma_session(
    state: str, irma_provider: IRMAProvider = Depends(Provide["services.irma_provider"])
):
    return irma_provider.irma_session(state)


@irma_router.get("/irma/result")
@inject
def irma_session(
    state: str, irma_provider: IRMAProvider = Depends(Provide["services.irma_provider"])
):
    return irma_provider.handle_irma_result(state)
