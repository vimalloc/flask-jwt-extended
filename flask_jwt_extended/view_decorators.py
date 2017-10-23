from functools import wraps

from flask import request
from werkzeug.security import safe_str_cmp
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import (
    InvalidHeaderError, NoAuthorizationError, WrongTokenError,
    FreshTokenRequired, CSRFError, UserLoadError, RevokedTokenError,
    UserClaimsVerificationError
)
from flask_jwt_extended.tokens import decode_jwt
from flask_jwt_extended.utils import (
    has_user_loader, user_loader, token_in_blacklist,
    has_token_in_blacklist_callback, verify_token_claims
)


def jwt_required(fn):
    """
    A decorator to protect a Flask endpoint.

    If you decorate an endpoint with this, it will ensure that the requester
    has a valid access token before allowing the endpoint to be called. This
    does not check the freshness of the access token.

    See also: :func:`~flask_jwt_extended.fresh_jwt_required`
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jwt_data = _decode_jwt_from_request(request_type='access')
        ctx_stack.top.jwt = jwt_data
        if not verify_token_claims(jwt_data[config.user_claims]):
            raise UserClaimsVerificationError('User claims verification failed')
        _load_user(jwt_data[config.identity_claim])
        return fn(*args, **kwargs)
    return wrapper


def jwt_optional(fn):
    """
    A decorator to optionally protect a Flask endpoint

    If an access token in present in the request, this will call the endpoint
    with :func:`~flask_jwt_extended.get_jwt_identity` having the identity
    of the access token. If no access token is present in the request,
    this endpoint will still be called, but
    :func:`~flask_jwt_extended.get_jwt_identity` will return `None` instead.

    If there is an invalid access token in the request (expired, tampered with,
    etc), this will still call the appropriate error handler instead of allowing
    the endpoint to be called as if there is no access token in the request.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            jwt_data = _decode_jwt_from_request(request_type='access')
            ctx_stack.top.jwt = jwt_data
            if not verify_token_claims(jwt_data[config.user_claims]):
                raise UserClaimsVerificationError('User claims verification failed')
            _load_user(jwt_data[config.identity_claim])
        except (NoAuthorizationError, InvalidHeaderError):
            pass
        return fn(*args, **kwargs)
    return wrapper


def fresh_jwt_required(fn):
    """
    A decorator to protect a Flask endpoint.

    If you decorate an endpoint with this, it will ensure that the requester
    has a valid and fresh access token before allowing the endpoint to be
    called.

    See also: :func:`~flask_jwt_extended.jwt_required`
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jwt_data = _decode_jwt_from_request(request_type='access')
        ctx_stack.top.jwt = jwt_data
        if not jwt_data['fresh']:
            raise FreshTokenRequired('Fresh token required')
        if not verify_token_claims(jwt_data[config.user_claims]):
            raise UserClaimsVerificationError('User claims verification failed')
        _load_user(jwt_data[config.identity_claim])
        return fn(*args, **kwargs)
    return wrapper


def jwt_refresh_token_required(fn):
    """
    A decorator to protect a Flask endpoint.

    If you decorate an endpoint with this, it will ensure that the requester
    has a valid refresh token before allowing the endpoint to be called.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jwt_data = _decode_jwt_from_request(request_type='refresh')
        ctx_stack.top.jwt = jwt_data
        _load_user(jwt_data[config.identity_claim])
        return fn(*args, **kwargs)
    return wrapper


def _load_user(identity):
    if has_user_loader():
        user = user_loader(identity)
        if user is None:
            raise UserLoadError("user_loader returned None for {}".format(identity))
        else:
            ctx_stack.top.jwt_user = user


def _token_blacklisted(decoded_token, request_type):
    if not config.blacklist_enabled:
        return False
    if not has_token_in_blacklist_callback():
        raise RuntimeError("A token_in_blacklist_callback must be provided via "
                           "the '@token_in_blacklist_loader' if "
                           "JWT_BLACKLIST_ENABLED is True")

    if config.blacklist_access_tokens and request_type == 'access':
        return token_in_blacklist(decoded_token)
    if config.blacklist_refresh_tokens and request_type == 'refresh':
        return token_in_blacklist(decoded_token)
    return False


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

    return decode_jwt(
        encoded_token=token,
        secret=config.decode_key,
        algorithm=config.algorithm,
        csrf=False,
        identity_claim=config.identity_claim
    )


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
        csrf=config.csrf_protect,
        identity_claim=config.identity_claim
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
    if _token_blacklisted(decoded_token, request_type):
        raise RevokedTokenError('Token has been revoked')

    return decoded_token
