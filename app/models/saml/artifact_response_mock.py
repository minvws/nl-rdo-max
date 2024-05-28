from functools import cached_property
from typing import Union

from packaging.version import Version

from .artifact_response import ArtifactResponse, ArtifactResponseStatus


class ArtifactResponseMock(ArtifactResponse):
    def __init__(self, artifact_response_str) -> None:
        ArtifactResponse.__init__(
            self,
            artifact_response_str=artifact_response_str,
            artifact_tree=None,
            cluster_priv_key=None,
            priv_key="mock",
            expected_entity_id="mock",
            expected_service_uuid="mock",
            expected_response_destination="mock",
            sp_metadata=None,
            idp_metadata=None,
            saml_specification_version=Version("0.1"),
            is_verified=False,
            strict=False,
        )
        self.artifact_response_str = artifact_response_str

    def validate(self) -> None:
        pass

    def get_bsn(self, authorization_by_proxy: bool) -> str:
        return self.artifact_response_str

    @cached_property
    def loa_authn(self) -> Union[str, None]:
        return "http://eidas.europa.eu/LoA/substantial"

    @cached_property
    def saml_status(self) -> ArtifactResponseStatus:
        return ArtifactResponseStatus(code="success", message="mock")
