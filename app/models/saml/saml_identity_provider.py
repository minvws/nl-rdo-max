import logging
from functools import cached_property

import requests
from lxml import etree
from packaging.version import parse as version_parse

from app.exceptions.max_exceptions import UnauthorizedError
from app.misc.utils import file_content, file_content_raise_if_none, json_from_file
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.artifact_response_factory import ArtifactResponseFactory
from app.models.saml.exceptions import ScopingAttributesNotAllowed
from app.models.saml.metadata import IdPMetadata, SPMetadata
from app.models.saml.saml_request import ArtifactResolveRequest, AuthNRequest


class SamlIdentityProvider:  # pylint: disable=too-many-instance-attributes
    def __init__(self, name, idp_setting, jinja_env) -> None:
        self.name = name
        self.log: logging.Logger = logging.getLogger(__package__)

        self.jinja_env = jinja_env

        settings_dict = json_from_file(idp_setting["settings_path"])
        self._verify_ssl = idp_setting.get("verify_ssl", True)
        self._client_cert_with_key = (idp_setting["cert_path"], idp_setting["key_path"])
        self._idp_metadata = IdPMetadata(idp_setting["idp_metadata_path"])
        self._sp_metadata = SPMetadata(
            settings_dict, self._client_cert_with_key, self.jinja_env
        )
        self._authn_binding = settings_dict["idp"]["singleSignOnService"]["binding"]

        self._artifact_response_factory = ArtifactResponseFactory(
            cluster_key=file_content(idp_setting.get("cluster_key_path", None)),
            priv_key=file_content_raise_if_none(
                idp_setting.get("cluster_key_path", None)
            ),
            expected_service_uuid=idp_setting["expected_service_uuid"],
            expected_response_destination=idp_setting["expected_response_destination"],
            expected_entity_id=idp_setting["expected_entity_id"],
            sp_metadata=self._sp_metadata,
            idp_metadata=self._idp_metadata,
            saml_specification_version=version_parse(
                str(idp_setting["saml_specification_version"])
            ),
            strict=idp_setting.get("strict", True) is True,
            insecure=idp_setting.get("insecure", False) is True,
        )

    @cached_property
    def authn_binding(self):
        return self._authn_binding

    def create_authn_request(self, authorization_by_proxy, cluster_name=None):
        scoping_list, request_ids = self.determine_scoping_attributes(
            authorization_by_proxy
        )
        scoping_list = []  # todo: Remove this
        sso_url = self._idp_metadata.get_sso()["location"]

        return AuthNRequest(
            sso_url,
            self._sp_metadata,
            self.jinja_env,
            scoping_list=scoping_list,
            request_ids=request_ids,
            cluster_name=cluster_name,
        )

    def create_artifactresolve_request(self, artifact: str):
        sso_url = self._idp_metadata.get_sso()["location"]
        return ArtifactResolveRequest(
            artifact, sso_url, self._sp_metadata, self.jinja_env
        )

    def determine_scoping_attributes(self, authorization_by_proxy):
        if self._sp_metadata.allow_scoping:
            return (
                self.determine_scoping_list(authorization_by_proxy),
                self.determine_request_ids(authorization_by_proxy),
            )

        if authorization_by_proxy:
            raise ScopingAttributesNotAllowed(
                "Scoping for this provider has been disabled in the settings"
            )
        return [], []

    def determine_scoping_list(self, authorization_by_proxy):
        if authorization_by_proxy:
            return self._sp_metadata.authorization_by_proxy_scopes
        return self._sp_metadata.default_scopes

    def determine_request_ids(self, authorization_by_proxy):
        if authorization_by_proxy:
            return self._sp_metadata.authorization_by_proxy_request_ids
        return []

    def resolve_artifact(self, saml_artifact) -> ArtifactResponse:
        url = self._idp_metadata.get_artifact_rs()["location"]
        headers = {"SOAPAction": "resolve_artifact", "content-type": "text/xml"}
        resolve_artifact_req = self.create_artifactresolve_request(saml_artifact)

        # todo: test and fix this method
        # todo: error handling, raise for status
        # todo: catch faulty responses
        response = requests.post(
            url,
            headers=headers,
            data=resolve_artifact_req.get_xml(xml_declaration=True),
            cert=self._client_cert_with_key,
            verify=self._verify_ssl,
            timeout=30,  # seconds
        )
        try:
            return self._artifact_response_factory.from_string(
                xml_response=response.text,
            )
        except etree.XMLSyntaxError as xml_syntax_error:  # pylint: disable=c-extension-no-member
            self.log.debug(
                "XMLSyntaxError from external authorization: %s", xml_syntax_error
            )
            self.log.debug("Received SAMLart: %s", saml_artifact)
            raise UnauthorizedError(
                error_description="External authorization failed", redirect_uri=None
            ) from xml_syntax_error
