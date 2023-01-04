import abc
from typing import Any, Dict
#todo is this used?

class Userinfo(abc.ABC, dict):
    @abc.abstractmethod
    def get_irma_disclosure(self) -> Dict[str, Any]:
        pass
