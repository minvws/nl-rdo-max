class ScopeService:
    def __init__(self, settings):
        self.settings = settings

    @property
    def allowed_scopes(self):
        return self.settings.allowed_scopes

    def determine_scoping_list(self, scope):
        if not self.scope_allowed(scope):
            raise Exception("scope not allowed")

        if scope == 'authorization_by_proxy':
            return [
                    "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:0001",
                    "urn:nl-eid-gdi:1.0:BVD:00000004003214345001:entities:0001",
                ]

        return [
            "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:0001",
        ]

    def determine_request_ids(self, scope):
        if not self.scope_allowed(scope):
            raise Exception("scope not allowed")

        if scope == 'authorization_by_proxy':
            return [
                    "urn:nl-eid-gdi:1.0:BVD:00000004003214345001:entities:0001",
                ]

        return []
