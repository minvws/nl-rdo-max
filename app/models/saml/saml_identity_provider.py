import logging
from functools import cached_property

import requests
from lxml import etree
from packaging.version import parse as version_parse

from app.exceptions.max_exceptions import UnauthorizedError
from app.misc.utils import file_content_raise_if_none
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.artifact_response_factory import ArtifactResponseFactory
from app.models.saml.exceptions import ScopingAttributesNotAllowed
from app.models.saml.metadata import IdPMetadata, SPMetadata
from app.models.saml.saml_request import ArtifactResolveRequest, AuthNRequest


class SamlIdentityProvider:  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        name,
        base_dir,
        settings,
        jinja_env,
        external_http_requests_timeout_seconds,
    ) -> None:
        self.name = name
        self.base_dir = base_dir
        self.log: logging.Logger = logging.getLogger(__package__)

        self.jinja_env = jinja_env

        self._settings_dict = settings
        sp_settings = settings.get("sp", {})
        self._verify_ssl = settings.get("verify_ssl", True)
        self._client_cert_with_key = (
            sp_settings.get("cert_path"),
            sp_settings.get("key_path"),
        )
        self._idp_metadata = IdPMetadata(settings.get("idp", {}).get("metadata_path"))
        self._sp_metadata = SPMetadata(
            self._settings_dict, self._client_cert_with_key, self.jinja_env
        )
        self._authn_binding = self._settings_dict["idp"]["singleSignOnService"][
            "binding"
        ]

        self._artifact_response_factory = ArtifactResponseFactory(
            cluster_key=None,
            priv_key=file_content_raise_if_none(sp_settings.get("key_path", None)),
            expected_service_uuid=sp_settings["attributeConsumingService"][
                "requestedAttributes"
            ][0]["attributeValue"][0],
            expected_response_destination=sp_settings["assertionConsumerService"].get(
                "url"
            ),
            expected_entity_id=sp_settings.get("entityId"),
            sp_metadata=self._sp_metadata,
            idp_metadata=self._idp_metadata,
            saml_specification_version=version_parse(
                str(settings.get("saml_specification_version"))
            ),
            strict=settings.get("strict", True) is True,
            insecure=settings.get("insecure", False) is True,
        )
        self._external_http_requests_timeout_seconds = (
            external_http_requests_timeout_seconds
        )

    @cached_property
    def authn_binding(self):
        return self._authn_binding

    @cached_property
    def sp_metadata(self):
        return self._sp_metadata

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
        if self._settings_dict.get("security").get("allowScoping"):
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

    def resolve_artifact(self, saml_artifact: str) -> ArtifactResponse:
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
            timeout=self._external_http_requests_timeout_seconds,
        )
        try:
            return self._artifact_response_factory.from_string(
                xml_response=response.text,
            )
        except (
            etree.XMLSyntaxError  # pylint: disable=c-extension-no-member
        ) as xml_syntax_error:
            self.log.debug(
                "XMLSyntaxError from external authorization: %s", xml_syntax_error
            )
            self.log.debug("Received SAMLart: %s", saml_artifact)
            raise UnauthorizedError(
                error_description="External authorization failed"
            ) from xml_syntax_error
