
from pyop.exceptions import OAuthError

class UserNotAuthenticated(OAuthError):
    def __init__(self, message, error):
        super().__init__(message, error)
