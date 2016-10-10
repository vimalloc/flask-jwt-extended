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


class JWTEncodeError(JWTExtendedException):
    """
    An error encoding a JWT
    """
    pass


class InvalidHeaderError(JWTExtendedException):
    """
    An error getting header information from a request
    """
    pass


class NoAuthorizationError(JWTExtendedException):
    """
    An error getting header information from a request
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
    pass


class FreshTokenRequired(JWTExtendedException):
    """
    Error raised when a valid, non-fresh JWT attempt to access an endpoint
    protected by fresh_jwt_required
    """
    pass
