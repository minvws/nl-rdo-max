from lxml import etree
from packaging.version import Version

from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.metadata import IdPMetadata, SPMetadata
from .exceptions import ValidationError
from ...misc.saml_utils import has_valid_signatures


class ArtifactResponseFactory:
    def __init__(  # pylint: disable=too-many-arguments, too-many-positional-arguments
        self,
        priv_key: str,
        expected_entity_id: str,
        expected_service_uuid: str,
        expected_response_destination: str,
        sp_metadata: SPMetadata,
        idp_metadata: IdPMetadata,
        saml_specification_version: Version,
        strict: bool,
        insecure: bool,
    ):
        self._priv_key = priv_key
        self._expected_entity_id = expected_entity_id
        self._expected_service_uuid = expected_service_uuid
        self._expected_response_destination = expected_response_destination
        self._sp_metadata = sp_metadata
        self._idp_metadata = idp_metadata
        self._saml_specification_version = saml_specification_version
        self._strict = strict
        self._insecure = insecure

    def verify_signatures(
        self, tree: etree._Element
    ):  # pylint: disable=c-extension-no-member, protected-access
        signing_certificates = self._idp_metadata.get_signing_certificates()
        root, valid = has_valid_signatures(
            tree, signing_certificates=signing_certificates
        )
        if not valid:
            raise ValidationError("Invalid signatures")
        return root

    def from_string(self, xml_response: str):
        # Remove XML declaration if exists, appears etree doesn't handle it too well.
        artifact_str = xml_response.split('<?xml version="1.0" encoding="UTF-8"?>\n')[
            -1
        ]
        artifact_tree_root = (
            etree.fromstring(artifact_str)  # pylint: disable=c-extension-no-member
            .getroottree()
            .getroot()
        )

        if artifact_tree_root is None:
            raise ValidationError("Invalid XML response format")

        is_verified = False
        if not self._insecure:
            artifact_tree = self.verify_signatures(artifact_tree_root)
            is_verified = True
        else:
            artifact_tree = artifact_tree_root.find(
                ".//{http://schemas.xmlsoap.org/soap/envelope/}Body/"
                "{urn:oasis:names:tc:SAML:2.0:protocol}ArtifactResponse"
            )

        if artifact_tree is None:
            raise ValidationError("ArtifactResponse not found in the XML response")

        return ArtifactResponse(
            artifact_response_str=xml_response,
            artifact_tree=artifact_tree,
            priv_key=self._priv_key,
            expected_entity_id=self._expected_entity_id,
            expected_service_uuid=self._expected_service_uuid,
            expected_response_destination=self._expected_response_destination,
            sp_metadata=self._sp_metadata,
            idp_metadata=self._idp_metadata,
            saml_specification_version=self._saml_specification_version,
            is_verified=is_verified,
            strict=self._strict,
        )
