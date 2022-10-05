from fastapi import APIRouter, Request, Depends
from dependency_injector.wiring import inject, Provide

from app.providers.cc_provider import CCProvider
from app.models.enums import Version


cc_router = APIRouter()


@cc_router.get("/bsn_attribute")
@inject
def bsn_attribute(
    request: Request,
    cc_provider: CCProvider = Depends(Provide["services.cc_provider"])
):
    return cc_provider.bsn_attribute(request, version=Version.V1)
