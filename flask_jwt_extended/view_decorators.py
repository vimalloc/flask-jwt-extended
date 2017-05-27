from functools import wraps

from flask import request
from werkzeug.security import safe_str_cmp
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

from flask_jwt_extended.blacklist import check_if_token_revoked
from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import (
    InvalidHeaderError, NoAuthorizationError, WrongTokenError,
    FreshTokenRequired, CSRFError
)
from flask_jwt_extended.tokens import decode_jwt


def jwt_required(fn):
    """
    If you decorate a vew with this, it will ensure that the requester has a
    valid JWT before calling the actual view. This does not check the freshness
    of the token.

    See also: fresh_jwt_required()

    :param fn: The view function to decorate
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Save the jwt in the context so that it can be accessed later by
        # the various endpoints that is using this decorator
        jwt_data = _decode_jwt_from_request(request_type='access')
        ctx_stack.top.jwt = jwt_data
        return fn(*args, **kwargs)
    return wrapper


def jwt_optional(fn):
    """
    If you decorate a view with this, it will check the request for a valid
    JWT and put it into the Flask application context before calling the view.
    If no authorization header is present, the view will be called without the
    application context being changed. Other authentication errors are not
    affected.

    :param fn: The view function to decorate
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            # If an acceptable JWT is found in the request, put it into
            # the application context
            jwt_data = _decode_jwt_from_request(request_type='access')
            ctx_stack.top.jwt = jwt_data
        except NoAuthorizationError:
            # Allow request to proceed if no authorization header is present
            # in the request, but don't modify application context
            pass
        # Return the decorated function in either case
        return fn(*args, **kwargs)
    return wrapper


def fresh_jwt_required(fn):
    """
    If you decorate a vew with this, it will ensure that the requester has a
    valid JWT before calling the actual view.

    See also: jwt_required()

    :param fn: The view function to decorate
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Check if the token is fresh
        jwt_data = _decode_jwt_from_request(request_type='access')
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
        # Save the jwt in the context so that it can be accessed later by
        # the various endpoints that is using this decorator
        jwt_data = _decode_jwt_from_request(request_type='refresh')
        ctx_stack.top.jwt = jwt_data
        return fn(*args, **kwargs)
    return wrapper


def _decode_jwt_from_headers():
    header_name = config.header_name
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

    return decode_jwt(token, config.decode_key, config.algorithm, csrf=False)


def _decode_jwt_from_cookies(request_type):
    if request_type == 'access':
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
        secret=config.decode_key,
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


def _decode_jwt_from_request(request_type):
    # We have three cases here, having jwts in both cookies and headers is
    # valid, or the jwt can only be saved in one of cookies or headers. Check
    # all cases here.
    if config.jwt_in_cookies and config.jwt_in_headers:
        try:
            decoded_token = _decode_jwt_from_cookies(request_type)
        except NoAuthorizationError:
            try:
                decoded_token = _decode_jwt_from_headers()
            except NoAuthorizationError:
                raise NoAuthorizationError("Missing JWT in headers and cookies")
    elif config.jwt_in_headers:
        decoded_token = _decode_jwt_from_headers()
    else:
        decoded_token = _decode_jwt_from_cookies(request_type)

    # Make sure the type of token we received matches the request type we expect
    if decoded_token['type'] != request_type:
        raise WrongTokenError('Only {} tokens can access this endpoint'.format(request_type))

    # If blacklisting is enabled, see if this token has been revoked
    if config.blacklist_enabled:
        check_if_token_revoked(decoded_token)

    return decoded_token

