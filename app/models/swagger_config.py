from typing import Optional

from pydantic import BaseModel


class SwaggerConfig(BaseModel):
    enabled: bool
    swagger_ui_endpoint: Optional[str] = None
    redoc_endpoint: Optional[str] = None
    openapi_endpoint: Optional[str] = None
