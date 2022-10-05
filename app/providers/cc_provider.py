from fastapi import Request
from app.models.enums import Version


class CCProvider():
    def bsn_attribute(self, request: Request, version: Version):
        return ""
