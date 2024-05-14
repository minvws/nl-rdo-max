from enum import Enum


class Version(Enum):
    V1 = 1
    V2 = 2


class RedirectType(str, Enum):
    HTML = "html"
    HTTP = "http"


# pylint:disable=no-member
class ClientAssertionMethods(str, Enum):
    PRIVATE_KEY_JWT = "private_key_jwt"
    NONE = "none"

    @classmethod
    def to_list(cls):
        return list(map(lambda member: member.value, cls._member_map_.values()))
