from fastapi import APIRouter, Request, Depends
from dependency_injector.wiring import inject, Provide

from app.providers.irma_provider import IRMAProvider


irma_router = APIRouter()


@irma_router.get("/irma/session")
@inject
def authorize(
    request: Request,
    irma_provider: IRMAProvider = Depends(Provide["services.irma_provider"]),
):
    irma_provider.session()
