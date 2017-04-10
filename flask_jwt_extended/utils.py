from functools import wraps

from flask import request, current_app
from werkzeug.security import safe_str_cmp

from flask_jwt_extended.tokens import (
    decode_jwt, encode_refresh_token, encode_access_token
)

try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

from flask_jwt_extended.blacklist import check_if_token_revoked, store_token
from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import (
    InvalidHeaderError, NoAuthorizationError, WrongTokenError,
    FreshTokenRequired, CSRFError
)


def get_jwt_identity():
    """
    Returns the identity of the JWT in this context. If no JWT is present,
    None is returned.
    """
    return get_raw_jwt().get('identity', {})


def get_jwt_claims():
    """
    Returns the dictionary of custom use claims in this JWT. If no custom user
    claims are present, an empty dict is returned
    """
    return get_raw_jwt().get('user_claims', {})


def get_raw_jwt():
    """
    Returns the python dictionary which has all of the data in this JWT. If no
    JWT is currently present, and empty dict is returned
    """
    return getattr(ctx_stack.top, 'jwt', {})


def _get_cookie_max_age():
    """
    Checks config value for using session or persistent cookies and returns the
    appropriate value for flask set_cookies.
    """
    return None if config.session_cookie else 2147483647  # 2^31


def _decode_jwt_from_headers(type):
    # TODO make type an enum or something instead of a magic string
    if type == 'access':
        header_name = config.access_header_name
        header_type = config.header_type
    else:
        header_name = config.refresh_header_name
        header_type = config.header_type

    # Verify we have the auth header
    jwt_header = request.headers.get(header_name, None)
    if not jwt_header:
        raise NoAuthorizationError("Missing {} Header".format(header_name))

    # Make sure the header is in a valid format that we are expecting, ie
    # <HeaderName>: <HeaderType(optional)> <JWT>
    parts = jwt_header.split()
    if not header_type:
        if len(parts) != 1:
            msg = "Bad {} header. Expected value '<JWT>'".format(header_name)
            raise InvalidHeaderError(msg)
        token = parts[0]
    else:
        if parts[0] != header_type or len(parts) != 2:
            msg = "Bad {} header. Expected value '{} <JWT>'".format(header_name, header_type)
            raise InvalidHeaderError(msg)
        token = parts[1]

    return decode_jwt(token, config.secret_key, config.algorithm, csrf=False)


def _decode_jwt_from_cookies(type):
    # TODO make type an enum or something instead of a magic string
    if type == 'access':
        cookie_key = config.access_cookie_name
        csrf_header_key = config.access_csrf_header_name
    else:
        cookie_key = config.refresh_cookie_name
        csrf_header_key = config.refresh_csrf_header_name

    encoded_token = request.cookies.get(cookie_key)
    if not encoded_token:
        raise NoAuthorizationError('Missing cookie "{}"'.format(cookie_key))

    decoded_token = decode_jwt(
        encoded_token=encoded_token,
        secret=config.secret_key,
        algorithm=config.algorithm,
        csrf=config.csrf_protect
    )

    # Verify csrf double submit tokens match if required
    if config.csrf_protect and request.method in config.csrf_request_methods:
        csrf_token_in_token = decoded_token['csrf']
        csrf_token_in_header = request.headers.get(csrf_header_key, None)

        if not csrf_token_in_header:
            raise CSRFError("Missing CSRF token in headers")
        if not safe_str_cmp(csrf_token_in_header, csrf_token_in_token):
            raise CSRFError("CSRF double submit tokens do not match")

    return decoded_token


def _decode_jwt_from_request(type):
    # JWT can be in either headers or cookies
    if config.jwt_in_cookies and config.jwt_in_headers:
        try:
            return _decode_jwt_from_headers(type)
        except NoAuthorizationError:
            pass
        try:
            return _decode_jwt_from_cookies(type)
        except NoAuthorizationError:
            pass
        raise NoAuthorizationError("Missing JWT in header and cookies")

    # JWT can only be in headers
    elif config.jwt_in_headers:
        return _decode_jwt_from_headers(type)

    # JWT can only be in cookie
    else:
        return _decode_jwt_from_cookies(type)


def jwt_required(fn):
    """
    If you decorate a vew with this, it will ensure that the requester has a valid
    JWT before calling the actual view. This does not check the freshness of the
    token.

    See also: fresh_jwt_required()

    :param fn: The view function to decorate
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Attempt to decode the token
        jwt_data = _decode_jwt_from_request(type='access')

        # Verify this is an access token
        if jwt_data['type'] != 'access':
            raise WrongTokenError('Only access tokens can access this endpoint')

        # If blacklisting is enabled, see if this token has been revoked
        if config.blacklist_enabled:
            check_if_token_revoked(jwt_data)

        # Save the jwt in the context so that it can be accessed later by
        # the various endpoints that is using this decorator
        ctx_stack.top.jwt = jwt_data
        return fn(*args, **kwargs)
    return wrapper


def fresh_jwt_required(fn):
    """
    If you decorate a vew with this, it will ensure that the requester has a valid
    JWT before calling the actual view.

    See also: jwt_required()

    :param fn: The view function to decorate
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Attempt to decode the token
        jwt_data = _decode_jwt_from_request(type='access')

        # Verify this is an access token
        if jwt_data['type'] != 'access':
            raise WrongTokenError('Only access tokens can access this endpoint')

        # If blacklisting is enabled, see if this token has been revoked
        if config.blacklist_enabled:
            check_if_token_revoked(jwt_data)

        # Check if the token is fresh
        if not jwt_data['fresh']:
            raise FreshTokenRequired('Fresh token required')

        # Save the jwt in the context so that it can be accessed later by
        # the various endpoints that is using this decorator
        ctx_stack.top.jwt = jwt_data
        return fn(*args, **kwargs)
    return wrapper


def jwt_refresh_token_required(fn):
    """
    If you decorate a view with this, it will insure that the requester has a
    valid JWT refresh token before calling the actual view. If the token is
    invalid, expired, not present, etc, the appropriate callback will be called
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Get the JWT
        jwt_data = _decode_jwt_from_request(type='refresh')

        # verify this is a refresh token
        if jwt_data['type'] != 'refresh':
            raise WrongTokenError('Only refresh tokens can access this endpoint')

        # If blacklisting is enabled, see if this token has been revoked
        if config.blacklist_enabled:
            check_if_token_revoked(jwt_data)

        # Save the jwt in the context so that it can be accessed later by
        # the various endpoints that is using this decorator
        ctx_stack.top.jwt = jwt_data
        return fn(*args, **kwargs)
    return wrapper


def create_refresh_token(identity):
    """
    Creates a new refresh token

    :param identity: The identity of this token. This can be any data that is
                     json serializable. It can also be an object, in which case
                     you can use the user_identity_loader to define a function
                     that will be called to pull a json serializable identity
                     out of this object. This is useful so you don't need to
                     query disk twice, once for initially finding the identity
                     in your login endpoint, and once for setting addition data
                     in the JWT via the user_claims_loader
    :return: A new refresh token
    """
    # TODO this should be moved to the jwt manager
    refresh_token = encode_refresh_token(
        identity=current_app.jwt_manager._user_identity_callback(identity),
        secret=config.secret_key,
        algorithm=config.algorithm,
        expires_delta=config.refresh_expires,
        csrf=config.csrf_protect
    )

    # If blacklisting is enabled, store this token in our key-value store
    if config.blacklist_enabled:
        decoded_token = decode_jwt(refresh_token, config.secret_key,
                                   config.algorithm, csrf=config.csrf_protect)
        store_token(decoded_token, revoked=False)
    return refresh_token


def create_access_token(identity, fresh=False):
    """
    Creates a new access token

    :param identity: The identity of this token. This can be any data that is
                     json serializable. It can also be an object, in which case
                     you can use the user_identity_loader to define a function
                     that will be called to pull a json serializable identity
                     out of this object. This is useful so you don't need to
                     query disk twice, once for initially finding the identity
                     in your login endpoint, and once for setting addition data
                     in the JWT via the user_claims_loader
    :param fresh: If this token should be marked as fresh, and can thus access
                  fresh_jwt_required protected endpoints. Defaults to False
    :return: A new access token
    """
    # TODO this should be moved to the jwt manager
    access_token = encode_access_token(
        identity=current_app.jwt_manager._user_identity_callback(identity),
        secret=config.secret_key,
        algorithm=config.algorithm,
        expires_delta=config.access_expires,
        fresh=fresh,
        user_claims=current_app.jwt_manager._user_claims_callback(identity),
        csrf=config.csrf_protect
    )
    if config.blacklist_enabled:
        decoded_token = decode_jwt(access_token, config.secret_key,
                                   config.algorithm, csrf=config.csrf_protect)
        store_token(decoded_token, revoked=False)
    return access_token


def _get_csrf_token(encoded_token):
    secret = config.secret_key
    algorithm = config.algorithm
    token = decode_jwt(encoded_token, secret, algorithm, csrf=True)
    return token['csrf']


def set_access_cookies(response, encoded_access_token):
    """
    Takes a flask response object, and configures it to set the encoded access
    token in a cookie (as well as a csrf access cookie if enabled)
    """
    if not config.jwt_in_cookies:
        raise RuntimeWarning("set_access_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    # Set the access JWT in the cookie
    response.set_cookie(config.access_cookie_name,
                        value=encoded_access_token,
                        max_age=_get_cookie_max_age(),  # TODO move to config
                        secure=config.cookie_secure,
                        httponly=True,
                        path=config.access_cookie_path)

    # If enabled, set the csrf double submit access cookie
    if config.csrf_protect:
        response.set_cookie(config.access_csrf_cookie_name,
                            value=_get_csrf_token(encoded_access_token),
                            max_age=_get_cookie_max_age(),  # TODO move to config
                            secure=config.cookie_secure,
                            httponly=False,
                            path='/')


def set_refresh_cookies(response, encoded_refresh_token):
    """
    Takes a flask response object, and configures it to set the encoded refresh
    token in a cookie (as well as a csrf refresh cookie if enabled)
    """
    if not config.jwt_in_cookies:
        raise RuntimeWarning("set_refresh_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    # Set the refresh JWT in the cookie
    response.set_cookie(config.refresh_cookie_name,
                        value=encoded_refresh_token,
                        max_age=_get_cookie_max_age(),  # TODO move to config
                        secure=config.cookie_secure,
                        httponly=True,
                        path=config.refresh_cookie_path)

    # If enabled, set the csrf double submit refresh cookie
    if config.csrf_protect:
        response.set_cookie(config.refresh_csrf_cookie_name,
                            value=_get_csrf_token(encoded_refresh_token),
                            max_age=_get_cookie_max_age(),  # TODO move to config
                            secure=config.cookie_secure,
                            httponly=False,
                            path='/')


def unset_jwt_cookies(response):
    """
    Takes a flask response object, and configures it to unset (delete) the JWT
    cookies. Basically, this is a logout helper method if using cookies to store
    the JWT
    """
    if not config.jwt_in_cookies:
        raise RuntimeWarning("unset_refresh_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    response.set_cookie(config.refresh_cookie_name,
                        value='',
                        expires=0,
                        secure=config.cookie_secure,
                        httponly=True,
                        path=config.refresh_cookie_path)
    response.set_cookie(config.access_cookie_name,
                        value='',
                        expires=0,
                        secure=config.cookie_secure,
                        httponly=True,
                        path=config.access_cookie_path)

    if config.csrf_protect:
        response.set_cookie(config.refresh_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=config.cookie_secure,
                            httponly=False,
                            path='/')
        response.set_cookie(config.access_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=config.cookie_secure,
                            httponly=False,
                            path='/')

    return response
