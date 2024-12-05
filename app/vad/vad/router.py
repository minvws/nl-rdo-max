from fastapi import APIRouter

from vad.utils import resolve_instance
from vad.vad.schemas import UserInfoDTO
from vad.vad.service import BsnExchanger

router = APIRouter(tags=["vad"])


@router.get("/bsn/{bsn}/userinfo")
async def userinfo(
    bsn: str,
    bsn_exchanger: BsnExchanger = resolve_instance(BsnExchanger),
) -> UserInfoDTO:
    exchanged_bsn_data: UserInfoDTO = await bsn_exchanger.exchange(bsn=bsn)
    return exchanged_bsn_data
