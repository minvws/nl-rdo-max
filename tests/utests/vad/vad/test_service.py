from logging import Logger
import pytest

from pytest_mock import MockerFixture

from app.vad.brp.repositories import MockBrpRepository
from app.vad.brp.service import BrpService
from app.vad.prs.repositories import MockPrsRepository
from app.vad.prs.schemas import PrsResponseData
from app.vad.vad.service import BsnExchanger
from app.vad.vad.schemas import UserInfoDTO
from app.vad.brp.schemas import PersonDTO

class TestBsnExchanger:
    @pytest.mark.asyncio
    async def test_exchange(self, mocker: MockerFixture) -> None:
        # Mock the dependencies
        prs_repository = MockPrsRepository()
        brp_service = BrpService(brp_repository=MockBrpRepository(), logger=mocker.Mock(Logger))

        # Create an instance of BsnExchanger with mocked dependencies
        bsn_exchanger = BsnExchanger(prs_repository=prs_repository, brp_service=brp_service)

        # Define test data
        bsn = "123456789"
        reference_pseudonym = PrsResponseData(rid="encoded_rid", pdn="encoded_pdn")
        person = PersonDTO(age=42, name={"first_name": "Jan", "prefix": "van", "last_name": "Jansen", "initials": "J.", "full_name": "Jan van Jansen"})

        # Call the method under test
        result: UserInfoDTO = await bsn_exchanger.exchange(bsn)

        # Assert the result
        assert isinstance(result, UserInfoDTO)
        assert isinstance(result.reference_pseudonym, PrsResponseData)
        assert result.reference_pseudonym.rid is not None
        assert result.person == person
