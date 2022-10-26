from pyop.storage import StorageBase
from pyop.subject_identifier import SubjectIdentifierFactory

class AuthorizationState(object):
    KEY_AUTHORIZATION_REQUEST: str

    def __init__(
        self,
        subject_identifier_factory: SubjectIdentifierFactory,
        authorization_code_db: StorageBase = ...,
        access_token_db: StorageBase = ...,
        refresh_token_db: StorageBase = ...,
        subject_identifier_db: StorageBase = ...,
        *,
        authorization_code_lifetime: int = ...,
        access_token_lifetime: int = ...,
        refresh_token_lifetime: int = ...,
        refresh_token_threshold: int = ...
    ) -> None: ...
