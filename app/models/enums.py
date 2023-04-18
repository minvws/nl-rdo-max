from enum import Enum


class Version(Enum):
    V1 = 1
    V2 = 2


class SomethingWrongReason(str, Enum):
    OUTAGE = "outage"
    TOO_BUSY = "too_busy"
    TOO_MANY_REQUEST = "too_many_requests"
    AUTH_BY_PROXY_DISABLED = "auth_by_proxy_disabled"


class RedirectType(str, Enum):
    HTML = "html"
    HTTP = "http"
