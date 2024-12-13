import base64

import pytest
from httpx import AsyncClient, HTTPStatusError, RequestError
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
    async def test_api_prs_repository_get_pseudonym(
        self, mocker: MockerFixture
    ) -> None:
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
    async def test_api_prs_repository_handle_request_http_error(
        self, mocker: MockerFixture
    ) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = HTTPStatusError(
            "HTTP error",
            request=mocker.Mock(),
            response=mocker.Mock(status_code=500, text="Internal Server Error"),
        )

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(
            RuntimeError, match="HTTP error occurred: 500 - Internal Server Error"
        ):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_handle_request_request_error(
        self, mocker: MockerFixture
    ) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = RequestError("Request error")

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="Request error occurred: Request error"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_handle_request_unexpected_error(
        self, mocker: MockerFixture
    ) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = Exception("Unexpected error")

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(
            RuntimeError, match="An unexpected error occurred: Unexpected error"
        ):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_success(
        self, mocker: MockerFixture
    ) -> None:
        base_url = "https://api.example.com"
        organisation_id = "test_org_id"
        bsn = "123456789"

        rid_response = {"rid": "encoded_rid"}
        pdn_response = {"pdn": "encoded_pdn"}

        mock_post = mocker.patch.object(
            AsyncClient,
            "post",
            side_effect=[
                mocker.Mock(status_code=200, json=lambda: rid_response),
                mocker.Mock(status_code=200, json=lambda: pdn_response),
            ],
        )

        repository = ApiPrsRepository(
            client=AsyncClient(),
            repo_base_url=base_url,
            organisation_id=organisation_id,
        )
        result = await repository.get_pseudonym(bsn)

        assert result == PrsResponseData(rid="encoded_rid", pdn="encoded_pdn")

        assert result.rid == rid_response["rid"]
        assert result.pdn == pdn_response["pdn"]
        mock_post.assert_any_call(f"{base_url}/bsn/exchange/rid?bsn={bsn}")
        mock_post.assert_any_call(
            f"{base_url}/org_pseudonym?bsn={bsn}&org_id={organisation_id}"
        )

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_unexpected_error(
        self, mocker: MockerFixture
    ) -> None:
        client = mocker.AsyncMock()
        client.post.side_effect = Exception("Unexpected error")

        repository = ApiPrsRepository(client, "http://localhost", "test-org-id")
        bsn = "123456789"

        with pytest.raises(
            RuntimeError, match="An unexpected error occurred: Unexpected error"
        ):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_invalid_response(
        self, mocker: MockerFixture
    ) -> None:
        async_client_mock = mocker.Mock(AsyncClient)
        async_client_mock.post.side_effect = []

        repository = ApiPrsRepository(
            async_client_mock, "http://localhost", "test-org-id"
        )
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="An unexpected error occurred: "):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_empty_rid_response(
        self, mocker: MockerFixture
    ) -> None:
        async_client_mock = mocker.Mock(AsyncClient)

        rid_response: dict[str, str] = {}
        pdn_response: dict[str, str] = {"pdn": "encoded_pdn"}

        async_client_mock.post.side_effect = [
            mocker.Mock(status_code=200, json=lambda: rid_response),
            mocker.Mock(status_code=200, json=lambda: pdn_response),
        ]

        repository = ApiPrsRepository(
            async_client_mock, "http://localhost", "test-org-id"
        )
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="Received empty response"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_empty_pdn_response(
        self, mocker: MockerFixture
    ) -> None:
        async_client_mock = mocker.Mock(AsyncClient)

        rid_response: dict[str, str] = {"rid": "encoded_rid"}
        pdn_response: dict[str, str] = {}

        async_client_mock.post.side_effect = [
            mocker.Mock(status_code=200, json=lambda: rid_response),
            mocker.Mock(status_code=200, json=lambda: pdn_response),
        ]

        repository = ApiPrsRepository(
            async_client_mock, "http://localhost", "test-org-id"
        )
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="Received empty response"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_invalid_rid_response(
        self, mocker: MockerFixture
    ) -> None:
        async_client_mock = mocker.Mock(AsyncClient)

        rid_response: dict[str, str] = {"invalid": "true"}
        pdn_response: dict[str, str] = {"pdn": "encoded_pdn"}

        async_client_mock.post.side_effect = [
            mocker.Mock(status_code=200, json=lambda: rid_response),
            mocker.Mock(status_code=200, json=lambda: pdn_response),
        ]

        repository = ApiPrsRepository(
            async_client_mock, "http://localhost", "test-org-id"
        )
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="RID not found in response data"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_get_pseudonym_invalid_pdn_response(
        self, mocker: MockerFixture
    ) -> None:
        async_client_mock = mocker.Mock(AsyncClient)

        rid_response: dict[str, str] = {"rid": "encoded_rid"}
        pdn_response: dict[str, str] = {"invalid": "true"}

        async_client_mock.post.side_effect = [
            mocker.Mock(status_code=200, json=lambda: rid_response),
            mocker.Mock(status_code=200, json=lambda: pdn_response),
        ]

        repository = ApiPrsRepository(
            async_client_mock, "http://localhost", "test-org-id"
        )
        bsn = "123456789"

        with pytest.raises(RuntimeError, match="PDN not found in response data"):
            await repository.get_pseudonym(bsn)

    @pytest.mark.asyncio
    async def test_api_prs_repository_uses_bound_organisation_id(
        self, mocker: MockerFixture
    ) -> None:
        async_client_mock = mocker.Mock(AsyncClient)
        mock_id = "test_organisation_id"

        async_client_mock.post.side_effect = [
            mocker.Mock(status_code=200, json=lambda: {"rid": "encoded_rid"}),
            mocker.Mock(status_code=200, json=lambda: {"pdn": "encoded_pdn"}),
        ]

        repository = ApiPrsRepository(
            async_client_mock, "http://localhost", organisation_id=mock_id
        )
        bsn = "123456789"

        await repository.get_pseudonym(bsn)
        second_call = async_client_mock.post.call_args_list[1]
        assert (
            second_call[0][0]
            == f"http://localhost/org_pseudonym?bsn={bsn}&org_id=test_organisation_id"
        )
