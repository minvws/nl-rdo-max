from fastapi import APIRouter, Request, Depends
from dependency_injector.wiring import inject, Provide

from app.providers.uzi_provider import UziProvider


userinfo_router = APIRouter()


