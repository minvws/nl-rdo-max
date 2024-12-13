import asyncio
import base64
from abc import ABC, abstractmethod
from typing import Dict

import inject
from httpx import AsyncClient, HTTPStatusError, RequestError

from .schemas import PrsResponseData


class PrsRepository(ABC):
    @abstractmethod
    async def get_pseudonym(self, bsn: str) -> PrsResponseData: ...  # pragma: no cover


class MockPrsRepository(PrsRepository):
    async def get_pseudonym(self, bsn: str) -> PrsResponseData:
        return PrsResponseData(
            rid=base64.b64encode(bsn.encode()).decode(),
            pdn=base64.b64encode(bsn.encode()).decode(),
        )


class ApiPrsRepository(PrsRepository):
    @inject.autoparams()
    def __init__(
        self, client: AsyncClient, repo_base_url: str, organisation_id: str
    ) -> None:
        self.client = client
        self._repo_base_url = repo_base_url
        self._organisation_id = organisation_id

    async def _handle_request(self, url: str) -> Dict[str, str]:
        try:
            response = await self.client.post(url)
            response.raise_for_status()
            data = response.json()

            if not data:
                raise RuntimeError("Received empty response")

            if not isinstance(data, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in data.items()
            ):
                raise RuntimeError(
                    "Response data is not in the expected format of Dict[str, str]"
                )

            return data
        except HTTPStatusError as e:
            raise RuntimeError(
                f"HTTP error occurred: {e.response.status_code} - {e.response.text}"
            ) from e
        except RequestError as e:
            raise RuntimeError(f"Request error occurred: {str(e)}") from e
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred: {str(e)}") from e

    async def get_pseudonym(self, bsn: str) -> PrsResponseData:
        rid_url = f"{self._repo_base_url}/bsn/exchange/rid?bsn={bsn}"
        pdn_url = f"{self._repo_base_url}/org_pseudonym?bsn={bsn}&org_id={self._organisation_id}"

        rid_data, pdn_data = await asyncio.gather(
            self._handle_request(rid_url),
            self._handle_request(pdn_url),
        )

        if "rid" not in rid_data:
            raise RuntimeError("RID not found in response data")

        if "pdn" not in pdn_data:
            raise RuntimeError("PDN not found in response data")

        rid = rid_data.get("rid")
        assert rid is not None
        pdn = pdn_data.get("pdn")
        assert pdn is not None

        return PrsResponseData(rid=rid, pdn=pdn)
