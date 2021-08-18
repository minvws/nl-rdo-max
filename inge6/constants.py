from enum import Enum

class SectorNumber(Enum):
    BSN = 1
    SOFI = 2

class IdPName(Enum):
    TVS = 'tvs'
    DIGID = 'digid'


SECTOR_CODES = {
    's00000000': SectorNumber.BSN,
    's00000001': SectorNumber.SOFI,
}
