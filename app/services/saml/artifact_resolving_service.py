from typing import Any, Dict


class ArtifactResolvingService:
    def resolve_artifact(self, acs_context: dict) -> Dict[str, Any]:
        pass


class MockedArtifactResolvingService(ArtifactResolvingService):
    def resolve_artifact(self, acs_context: dict) -> Dict[str, Any]:
        if not acs_context["mocking"]:
            return super().resolve_artifact(acs_context)
        return {
            "bsn": acs_context["artifact"],
            "authorization_by_proxy": acs_context["authorization_by_proxy"],
            "mocking": True,
        }
