from typing import Text

from packaging.version import Version

from .artifact_response import ArtifactResponse


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

    def get_bsn(self, authorization_by_proxy: bool) -> Text:
        return self.artifact_response_str
