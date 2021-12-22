from pyop.exceptions import OAuthError


class UserNotAuthenticated(OAuthError):
    pass


class ValidationError(RuntimeError):
    pass


class ScopingAttributesNotAllowed(RuntimeError):
    pass
