from typing import Dict, Any

from app.models.userinfo.userinfo import Userinfo


class UziUserinfo(Userinfo):
    def get_irma_disclosure(self) -> Dict[str, Any]:
        pass

    @staticmethod
    def from_irma_disclosure(irma_disclosure: Dict[str, Any]):
        #todo: Should this be removed?
        # cibg_disclosure = {"roles": []}
        # disclosed = acs_context["acs_context"]
        # for item in disclosed:
        #     if item["id"] == f"{IRMA_PREFIX}.uraName":
        #         cibg_disclosure["ura_name"] = item['rawvalue']
        #     elif item["id"] == f"{IRMA_PREFIX}.uraNumber":
        #         cibg_disclosure["ura_number"] = item['rawvalue']
        #     elif item["id"] == f"{IRMA_PREFIX}.uziNumber":
        #         cibg_disclosure["uzi_number"] = item['rawvalue']
        #     elif item["id"].startswith(f"{IRMA_PREFIX}.hasRole"):
        #         if item["rawvalue"] == "yes":
        #             role = item["id"][len(IRMA_PREFIX) + 1:]
        #             role.replace("-", ".")
        #             cibg_disclosure["roles"].append(role)
        # client: Dict[str, Any] = None
        # for client_id in self._clients:
        #     if self._clients[client_id]["external_id"] == cibg_disclosure["ura_number"]:
        #         client = self._clients[client_id]
        #         break
        pass
