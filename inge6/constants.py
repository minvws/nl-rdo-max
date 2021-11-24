import os
from enum import Enum

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

SCOPE_AUTHORIZATION_BY_PROXY = "authorization_by_proxy"

class Version(Enum):
    V1 = 1
    V2 = 2

class BSNStorage(Enum):
    RECRYPTED = "recrypted"
    CLUSTERED = "clustered"


class SectorNumber(Enum):
    BSN = 1
    SOFI = 2


class RedisKeys(Enum):
    AUTH_REQ = "auth_req"
    CC_CM = "cc_cm"
    ARTI = "arti"


SECTOR_CODES = {
    "s00000000": SectorNumber.BSN,
    "s00000001": SectorNumber.SOFI,
}
