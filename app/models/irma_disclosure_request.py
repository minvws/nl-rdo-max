from typing import Any, Dict

from pydantic import BaseModel


class IRMADisclosureRequest(BaseModel):
    disclosure_context: Dict[str, Any]
