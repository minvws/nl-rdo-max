from typing import Union

from pydantic import BaseModel

from app.models.login_method_type import LoginMethodType


class LoginMethod(BaseModel):
    name: str
    logo: Union[str, None] = None
    text: str = ""
    type: LoginMethodType
    hidden: bool = False


class LoginMethodWithLink(LoginMethod):
    url: str
