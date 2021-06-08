from .idp_metadata import IdPMetadataParser
from .sp_metadata import SPMetadata

class Provider:

    def __init__(self) -> None:
        self._idp_metadata = IdPMetadataParser()
        self._sp_metadata = SPMetadata()

    @property
    def sp_metadata(self):
        return self._sp_metadata
    
    @property
    def idp_metadata(self):
        return self._idp_metadata
    