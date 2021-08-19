from enum import Enum

class SectorNumber(Enum):
    BSN = 1
    SOFI = 2

class RedisKeys(Enum):
    AUTH_REQ = 'auth_req'
    CC_CM = 'cc_cm'
    ARTI = 'arti'

SECTOR_CODES = {
    's00000000': SectorNumber.BSN,
    's00000001': SectorNumber.SOFI,
}
