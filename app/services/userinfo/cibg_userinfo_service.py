import json
import logging
from typing import Dict, Any

import requests
from lxml.etree import XMLSyntaxError

from app.exceptions.max_exceptions import ServerErrorException
from app.misc.utils import file_content_raise_if_none
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.services.encryption.jwe_service import JweService
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__name__)


class CIBGUserinfoService(UserinfoService):
    def __init__(
            self
    ):
        # todo: Move userinfo services to saml
        pass

    def _load_artifact_response(
            self,
            authentication_context: AuthenticationContext,
            saml_artifact: str,
            saml_identity_provider: SamlIdentityProvider,
            strict=True,
            use_cluster_key=False
    ) -> ArtifactResponse:
        try:
            return ArtifactResponse.from_string(
                saml_artifact,
                saml_identity_provider,
                strict=strict,
                use_cluster_key=use_cluster_key
            )
        except XMLSyntaxError as syntax_error:
            log.warning(
                f"Artifact is invalid XML, "
                f"this can happen when a client reuses the same acs response url: {syntax_error}"
            )
            raise ServerErrorException(
                error_description="Authorization url expired",
                redirect_uri=authentication_context.authorization_request["redirect_uri"]
            )

    def request_userinfo_for_artifact(
            self,
            authentication_context: AuthenticationContext,
            saml_artifact: str,
            saml_identity_provider: SamlIdentityProvider,
    ) -> str:
        artifact_response = self._load_artifact_response(authentication_context, saml_artifact, saml_identity_provider)
        raise Exception("unimplemented")

# todo: Get rid of the unimplemented exception
    def from_irma_disclosure(self, irma_disclosure):
        raise Exception("unimplemented")

    def irma_disclosure(self, userinfo: Dict[Any, Any]):
        if len(userinfo["relations"]) != 1:
            raise ValueError("Unable to disclose more than 1 relation")
        relation = userinfo["relations"][0]
        pload = {
            "@context": "https://irma.app/ld/request/issuance/v2",
            "credentials": [
                {
                    "credential": "irma-demo.uzipoc-cibg.uzi",
                    "attributes": {
                        "uraName": relation["entity_name"],
                        "uraNumber": relation["ura"],
                        "uziNumber": userinfo["uzi_id"],
                        "hasRole01-041": "yes" if "01.041" in relation["roles"] else "no",
                        "hasRole30-000": "yes" if "30.000" in relation["roles"] else "no",
                        "hasRole01-010": "yes" if "01.010" in relation["roles"] else "no",
                        "hasRole01-011": "yes" if "01.011" in relation["roles"] else "no",
                    },
                }
            ],
        }
        # todo: remove
        # pload = {
        #     "@context": "https://irma.app/ld/request/issuance/v2",
        #     "credentials": [
        #         {
        #             "credential": "irma-demo.uzipoc-cibg.uzi",
        #             "attributes": {
        #                 "initials": userinfo["initials"],
        #                 "surname_prefix": userinfo["surname_prefix"],
        #                 "surname": userinfo["surname"],
        #                 "entity_name": relation["entity_name"],
        #                 "ura": relation["ura"],
        #                 "uzi_id": userinfo["uzi_id"],
        #                 "roles": ",".join(relation["roles"]),
        #                 "loa_authn": userinfo["loa_authn"],
        #                 "loa_uzi": userinfo["loa_uzi"]
        #             },
        #         }
        #     ],
        # }
        resp = requests.post(
            f"http://localhost:4544/session", # todo: Move to the config
            headers={"Content-Type": "application/json"},
            data=json.dumps(pload),
        ).json()
        return resp["sessionPtr"]

# todo: Move to seperate class
class MockedCIBGUserinfoService(CIBGUserinfoService):
    def __init__(self, jwe_service: JweService, clients: dict, environment: str, mock_cibg: bool):
        super().__init__()
        self._jwe_service = jwe_service
        self._clients = clients
        self._environment = environment
        self._mock_cibg = mock_cibg

    def request_userinfo_for_artifact(
            self,
            authentication_context: AuthenticationContext,
            saml_artifact: str,
            saml_identity_provider: SamlIdentityProvider
    ) -> str:
        if self._environment.startswith("prod"):
            raise ServerErrorException(
                error_description="Invalid configuration. Mocking not allowed",
                redirect_uri=authentication_context.authorization_request["redirect_uri"]
            )
        if not self._mock_cibg and not authentication_context.authentication_method.endswith("mock"):
            return super().request_userinfo_for_artifact(
                authentication_context,
                saml_artifact,
                saml_identity_provider
            )
        if len(saml_artifact) > 9:
            artifact_response = self._load_artifact_response(
                authentication_context,
                saml_artifact,
                saml_identity_provider,
                strict=False,
                use_cluster_key=True,
            )
            bsn = artifact_response.get_bsn(False)
        else:
            bsn = saml_artifact
        relations = []
        client = self._clients[authentication_context.authorization_request["client_id"]]
        if "disclosure_clients" in client:
            for disclosure_client in client["disclosure_clients"]:
                relations.append(
                    {
                        "ura": self._clients[disclosure_client]["external_id"],
                        "entity_name": self._clients[disclosure_client]["name"],
                        "roles": ["01.041", "30.000", "01.010", "01.011"]
                    }
                )
        else:
            relations.append(
                {
                    "ura": client["external_id"],
                    "entity_name": client["name"],
                    "roles": ["01.041", "30.000", "01.010", "01.011"]
                }
            )
        return self._jwe_service.to_jwe(
            {
                # todo create json schema
                "json_schema": "https://www.inge6.nl/json_schema_v1.json",
                "initials": "J.J",
                "surname_prefix": "van der",
                "surname": "Jansen",
                "loa_authn": "substantial",
                "loa_uzi": "substantial",
                "uzi_id": bsn,
                "relations": relations,
                "client_claims": authentication_context.authorization_request["claims"].to_dict()
            },
            file_content_raise_if_none(
                client["client_certificate_path"]
            ),
        )
