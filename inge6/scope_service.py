class ScopeService:
    def __init__(self, settings):
        self.settings = settings

    @property
    def allowed_scopes(self):
        return self.settings.allowed_scopes

    def validate_scopes(self, scopes):
        for scope in scopes:
            if scope not in self.allowed_scopes:
                raise Exception(
                    f"scope {scope} not allowed, only {self.allowed_scopes} are supported"
                )

    def determine_scoping_list(self, scopes):
        scopes_arr = scopes.split()
        self.validate_scopes(scopes_arr)
        if "authorization_by_proxy" in scopes_arr:
            return [
                "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:0001",
                "urn:nl-eid-gdi:1.0:BVD:00000004003214345001:entities:0001",
            ]

        return [
            "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:0001",
        ]

    def determine_request_ids(self, scopes):
        scopes_arr = scopes.split()
        self.validate_scopes(scopes_arr)
        if "authorization_by_proxy" in scopes_arr:
            return [
                "urn:nl-eid-gdi:1.0:BVD:00000004003214345001:entities:0001",
            ]

        return []
