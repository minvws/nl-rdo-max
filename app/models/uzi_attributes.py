from pydantic import BaseModel


class UziAttributes(BaseModel):
    initials: str
    surname_prefix: str
    surname: str
    loa_authn: str
    loa_uzi: str
