from typing import Dict, Union, Sequence, Mapping, Any, Optional
from jwkest.jwk import Key

from pyop.authz_state import AuthorizationState
from pyop.userinfo import Userinfo

class Provider(object):
    def __init__(
        self,
        signing_key: Key,
        configuration_information: Dict[str, Union[str, Sequence[str]]],
        authz_state: AuthorizationState,
        clients: Mapping[str, Mapping[str, Any]],
        userinfo: Userinfo,
        *,
        id_token_lifetime: int = ...,
        extra_scopes: Optional[Dict[str, None]] = ...
    ) -> None: ...
