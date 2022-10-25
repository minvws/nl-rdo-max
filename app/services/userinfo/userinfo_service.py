from typing import Any, Text, Optional, Dict
import abc


class UserinfoService(abc.ABC):
    @abc.abstractmethod
    def request_userinfo_for_artifact(
        self, acs_context: Dict[str, Any], resolved_artifact: Dict[str, Any]
    ) -> str:
        pass
