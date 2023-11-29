from pydantic import BaseModel


class LoginMethod(BaseModel):
    name: str
    logo: str
    text: str
