import logging

from app.exceptions.max_exceptions import ServerErrorException
from app.misc.utils import file_content_raise_if_none
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.userinfo.cibg_userinfo_service import CIBGUserinfoService

log = logging.getLogger(__name__)

# pylint: disable=too-many-arguments
class MockedCIBGUserinfoService(CIBGUserinfoService):
    def __init__(
        self,
        jwe_service_provider: JweServiceProvider,
        clients: dict,
        environment: str,
        mock_cibg: bool,
        userinfo_request_signing_priv_key_path: str,
        userinfo_request_signing_crt_path: str,
        cibg_exchange_token_endpoint: str,
        jwt_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
    ):
        super().__init__(
            userinfo_request_signing_priv_key_path,
            userinfo_request_signing_crt_path,
            clients,
            cibg_exchange_token_endpoint,
            jwt_issuer,
            jwt_expiration_duration,
            jwt_nbf_lag,
        )
        self._jwe_service_provider = jwe_service_provider
        self._clients = clients
        self._environment = environment
        self._mock_cibg = mock_cibg

    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider,
    ) -> str:
        if self._environment.startswith("prod"):
            raise ServerErrorException(
                error_description="Invalid configuration. Mocking not allowed"
            )
        if (
            not self._mock_cibg
            and not authentication_context.authentication_method.endswith("mock")
        ):
            return super().request_userinfo_for_digid_artifact(
                authentication_context, artifact_response, saml_identity_provider
            )
        bsn = artifact_response.get_bsn(False)
        uzi_id = "123456789" if bsn is None else bsn
        return self._create_mocked_cibg_response(authentication_context, uzi_id)

    def _create_mocked_cibg_response(self, authentication_context, uzi_id):
        relations = []
        client = self._clients[
            authentication_context.authorization_request["client_id"]
        ]
        if "disclosure_clients" in client:
            for disclosure_client in client["disclosure_clients"]:
                relations.append(
                    {
                        "ura": self._clients[disclosure_client]["external_id"],
                        "entity_name": self._clients[disclosure_client]["name"],
                        "roles": ["01.041", "30.000", "01.010", "01.011"],
                    }
                )
        else:
            relations.append(
                {
                    "ura": client["external_id"],
                    "entity_name": client["name"],
                    "roles": ["01.041", "30.000", "01.010", "01.011"],
                }
            )
        return self._jwe_service_provider.get_jwe_service(client["pubkey_type"]).to_jwe(
            {
                # todo create json schema
                "json_schema": "https://www.inge6.nl/json_schema_v1.json",
                "initials": "J.J",
                "surname_prefix": "van der",
                "surname": "Jansen",
                "loa_authn": "substantial",
                "loa_uzi": "substantial",
                "uzi_id": uzi_id,
                "relations": relations,
            },
            file_content_raise_if_none(client["client_public_key_path"]),
        )
