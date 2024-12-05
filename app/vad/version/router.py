from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.vad.utils import resolve_instance
from app.vad.version.models import VersionInfo

router = APIRouter()


@router.get("/")
def get_version(version_info: VersionInfo = resolve_instance(VersionInfo)) -> JSONResponse:
    return JSONResponse(version_info.model_dump())
