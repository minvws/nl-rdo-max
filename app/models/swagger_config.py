from typing import Optional

from pydantic import BaseModel


class SwaggerConfig(BaseModel):
    enabled: bool
    swagger_ui_endpoint: Optional[str]
    redoc_endpoint: Optional[str]
    openapi_endpoint: Optional[str]
