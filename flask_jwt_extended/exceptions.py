class JWTExtendedException(Exception):
    """
    Base except which all flask_jwt_extended errors extend
    """

    pass


class JWTDecodeError(JWTExtendedException):
    """
    An error decoding a JWT
    """

    pass


class InvalidHeaderError(JWTExtendedException):
    """
    An error getting header information from a request
    """

    pass


class NoAuthorizationError(JWTExtendedException):
    """
    An error raised when no authorization token was found in a protected endpoint
    """

    pass


class CSRFError(JWTExtendedException):
    """
    An error with CSRF protection
    """

    pass


class WrongTokenError(JWTExtendedException):
    """
    Error raised when attempting to use a refresh token to access an endpoint
    or vice versa
    """

    pass


class RevokedTokenError(JWTExtendedException):
    """
    Error raised when a revoked token attempt to access a protected endpoint
    """

    def __init__(self, jwt_header, jwt_data):
        super().__init__("Token has been revoked")
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data


class FreshTokenRequired(JWTExtendedException):
    """
    Error raised when a valid, non-fresh JWT attempt to access an endpoint
    protected by fresh_jwt_required
    """

    def __init__(self, message, jwt_header, jwt_data):
        super().__init__(message)
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data


class UserLookupError(JWTExtendedException):
    """
    Error raised when a user_lookup callback function returns None, indicating
    that it cannot or will not load a user for the given identity.
    """

    def __init__(self, message, jwt_header, jwt_data):
        super().__init__(message)
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data


class UserClaimsVerificationError(JWTExtendedException):
    """
    Error raised when the claims_verification_callback function returns False,
    indicating that the expected user claims are invalid
    """

    def __init__(self, message, jwt_header, jwt_data):
        super().__init__(message)
        self.jwt_header = jwt_header
        self.jwt_data = jwt_data
