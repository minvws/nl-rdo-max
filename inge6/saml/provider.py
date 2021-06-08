from .metadata import IdPMetadata, SPMetadata

class Provider:

    def __init__(self) -> None:
        self._idp_metadata = IdPMetadata()
        self._sp_metadata = SPMetadata()

    @property
    def sp_metadata(self):
        return self._sp_metadata

    @property
    def idp_metadata(self):
        return self._idp_metadata

