import base64

import pytest
from httpx import HTTPStatusError, RequestError
from pytest_mock import MockerFixture

from app.vad.prs.repositories import ApiPrsRepository, MockPrsRepository
from app.vad.prs.schemas import PrsResponseData


class TestMockPrsRepository:
    @pytest.mark.asyncio
    async def test_mock_prs_repository_get_pseudonym_with_str_bsn(self) -> None:
        repository: MockPrsRepository = MockPrsRepository()
        bsn: str = "123456789"
        pseudonym: PrsResponseData = await repository.get_pseudonym(bsn)

        assert isinstance(pseudonym, PrsResponseData)
        assert pseudonym.rid == base64.b64encode(bsn.encode()).decode()
        assert pseudonym.pdn == base64.b64encode(bsn.encode()).decode()

    @pytest.mark.asyncio
    async def test_mock_prs_repository_get_pseudonym(self) -> None:
        bsn = "123456789"
        repository: MockPrsRepository = MockPrsRepository()
        pseudonym: PrsResponseData = await repository.get_pseudonym(bsn)

        expected_pseudonym = base64.b64encode(bsn.encode()).decode()
        assert isinstance(pseudonym, PrsResponseData)
        assert pseudonym.rid == expected_pseudonym
        assert pseudonym.pdn == expected_pseudonym


class TestApiPrsRepository:
    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym(self, mocker: MockerFixture) -> None:
        bsn = "123456789"
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.return_value = {
            "rid": base64.b64encode(bsn.encode()).decode(),
            "pdn": base64.b64encode(bsn.encode()).decode(),
        }
        client.post.return_value.raise_for_status = mocker.Mock()

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        pseudonym = await repository.get_pseudonym(bsn)

        expected_pseudonym = base64.b64encode(bsn.encode()).decode()
        assert isinstance(pseudonym, PrsResponseData)
        assert pseudonym.rid == expected_pseudonym
        assert pseudonym.pdn == expected_pseudonym

    @pytest.mark.asyncio
    async def test_api_prs_repository_handle_request_http_error(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = HTTPStatusError(
            "HTTP error", request=mocker.Mock(), response=mocker.Mock(status_code=500, text="Internal Server Error")
        )

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="HTTP error occurred: 500 - Internal Server Error"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_handle_request_request_error(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = RequestError("Request error")

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="Request error occurred: Request error"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_handle_request_unexpected_error(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = Exception("Unexpected error")

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="An unexpected error occurred: Unexpected error"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_success(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.side_effect = [{"rid": "encoded_rid"}, {"pdn": "encoded_pdn"}]

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        result = await repository.get_pseudonym(bsn)

        assert result == PrsResponseData(rid="encoded_rid", pdn="encoded_pdn")

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_unexpected_error(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = Exception("Unexpected error")

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="An unexpected error occurred: Unexpected error"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_invalid_response(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.return_value = {}

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="Received empty response"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_empty_rid_response(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.side_effect = [{}, {"pdn": "encoded_pdn"}]

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="Received empty response"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_empty_pdn_response(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.side_effect = [{"rid": "encoded_rid"}, {}]

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="Received empty response"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_invalid_rid_response(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.side_effect = [{"invalid": "true"}, {"pdn": "encoded_pdn"}]

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="RID not found in response data"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_invalid_pdn_response(self, mocker: MockerFixture) -> None:
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.side_effect = [{"rid": "encoded_rid"}, {"invalid": "true"}]

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="PDN not found in response data"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_uses_bound_organisation_id(self, mocker: MockerFixture) -> None:
        mock_id = "test_organisation_id"
        client = mocker.AsyncMock()
        client.post.return_value.json = mocker.Mock()
        client.post.return_value.json.side_effect = [{"rid": "encoded_rid"}, {"pdn": "encoded_pdn"}]

        repository = ApiPrsRepository(client, "http://localhost", organisation_id=mock_id)
        bsn = "123456789"

        await repository.get_pseudonym(bsn)
        second_call = client.post.call_args_list[1]
        assert second_call[0][0] == f"http://localhost/org_pseudonym?bsn={bsn}&org_id=test_organisation_id"
