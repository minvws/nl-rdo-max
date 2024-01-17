import logging

from dependency_injector.wiring import inject, Provide
from redis.exceptions import RedisError

from fastapi import APIRouter, Depends
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app.dependency_injection.storage import RedisCache
from app.dependency_injection.config import RouterConfig

misc_router = APIRouter()

logger = logging.getLogger(__name__)


@misc_router.get(RouterConfig.health_endpoint)
@inject
async def health(
    config=Depends(Provide["storage.config"]),
    redis_cache: RedisCache = Depends(Provide["storage.cache"]),
) -> JSONResponse:
    try:
        redis_healthy = redis_cache.ping()
    except RedisError as exception:
        logger.exception(
            "Redis server is not reachable. Attempted: %s:%s, ssl=%s",
            config.redis_client.host,
            config.redis_client.port,
            config.redis_client.ssl,
            exc_info=exception,
        )
        redis_healthy = False

    healthy = redis_healthy
    response = {
        "healthy": healthy,
        "results": [{"healthy": redis_healthy, "service": "keydb"}],
    }

    return JSONResponse(
        content=jsonable_encoder(response), status_code=200 if healthy else 500
    )
