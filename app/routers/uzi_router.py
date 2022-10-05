from fastapi import APIRouter, Request, Depends
from dependency_injector.wiring import inject, Provide

from app.providers.uzi_provider import UziProvider


uzi_router = APIRouter()


@uzi_router.get("/userinfo")
@inject
def authorize(
    request: Request,
    uzi_provider: UziProvider = Depends(Provide["services.uzi_provider"]),
):
    uzi_provider.userinfo()
