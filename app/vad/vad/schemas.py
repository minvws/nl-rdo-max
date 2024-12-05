from pydantic import BaseModel, Field

from app.vad.brp.schemas import PersonDTO
from app.vad.prs.schemas import PrsResponseData


class VadResponse(BaseModel):
    jwe: str = Field(description="JWE token containing the encrypted userinfo")


class UserInfoDTO(BaseModel):
    reference_pseudonym: PrsResponseData
    person: PersonDTO
