from typing import List, Dict, Union

from app.models.login_method import LoginMethod
from app.models.login_method_type import LoginMethodType


def map_login_methods_json_to_list_of_objects(
    raw_login_methods: List[Dict[str, Union[str, bool]]],
) -> List[LoginMethod]:
    login_methods: List[LoginMethod] = []

    for raw_login_method in raw_login_methods:
        login_method = LoginMethod(
            name=get_string_from_dict(raw_login_method, "name"),
            logo=get_optional_string_from_dict(raw_login_method, "logo"),
            text=get_optional_string_from_dict(raw_login_method, "text") or "",
            type=LoginMethodType(get_string_from_dict(raw_login_method, "type")),
            hidden=get_optional_boolean_from_dict(raw_login_method, "hidden", False),
        )
        login_methods.append(login_method)

    return login_methods


def get_optional_string_from_dict(
    raw_login_method: Dict[str, Union[str, bool]], key: str
) -> Union[str, None]:
    if key not in raw_login_method:
        return None

    value = raw_login_method[key]
    if not isinstance(value, str):
        return None

    return value


def get_string_from_dict(
    raw_login_method: Dict[str, Union[str, bool]], key: str
) -> str:
    if key not in raw_login_method:
        raise ValueError(f"Key {key} not found in login method: {raw_login_method}")

    value = raw_login_method[key]
    if not isinstance(value, str):
        raise ValueError(
            f"Value of {key} is not a string in login method: {raw_login_method}"
        )

    return value


def get_optional_boolean_from_dict(
    raw_login_method: Dict[str, Union[str, bool]], key: str, default: bool = False
) -> bool:
    if key not in raw_login_method:
        return default

    value = raw_login_method[key]
    if not isinstance(value, bool):
        return default

    return value
