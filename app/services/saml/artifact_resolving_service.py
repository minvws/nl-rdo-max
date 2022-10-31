from typing import Any, Dict


class ArtifactResolvingService:
    def resolve_artifact(self, acs_context: dict) -> Dict[str, Any]:
        pass


class MockedArtifactResolvingService(ArtifactResolvingService):
    def resolve_artifact(self, acs_context: dict) -> Dict[str, Any]:
        # todo: check environment in every mocking service
        if not acs_context["mocking"]:
            return super().resolve_artifact(acs_context)
        return {
            "bsn": acs_context["artifact"],
            "authorization_by_proxy": acs_context["authorization_by_proxy"],
            "mocking": True,
        }
