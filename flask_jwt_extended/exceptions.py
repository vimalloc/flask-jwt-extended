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
