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

    def determine_scoping_attributes(self, scopes, id_provider):
        if id_provider.sp_metadata.allow_scoping:
            return (
                self.determine_scoping_list(scopes, id_provider),
                self.determine_request_ids(scopes, id_provider),
            )
        return [], []

    def determine_scoping_list(self, scopes, id_provider):
        scopes_arr = scopes.split()
        self.validate_scopes(scopes_arr)
        if "authorization_by_proxy" in scopes_arr:
            return id_provider.authorization_by_proxy_scopes
        return id_provider.sp_metadata.default_scopes

    def determine_request_ids(self, scopes, id_provider):
        scopes_arr = scopes.split()
        self.validate_scopes(scopes_arr)
        if "authorization_by_proxy" in scopes_arr:
            return id_provider.authorization_by_proxy_request_ids
        return []
