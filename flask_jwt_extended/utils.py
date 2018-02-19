from flask import current_app
from werkzeug.local import LocalProxy

try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import (
    RevokedTokenError, UserClaimsVerificationError, WrongTokenError
)
from flask_jwt_extended.tokens import decode_jwt


# Proxy to access the current user
current_user = LocalProxy(lambda: get_current_user())


def get_raw_jwt():
    """
    In a protected endpoint, this will return the python dictionary which has
    all of the claims of the JWT that is accessing the endpoint. If no
    JWT is currently present, an empty dict is returned instead.
    """
    return getattr(ctx_stack.top, 'jwt', {})


def get_jwt_identity():
    """
    In a protected endpoint, this will return the identity of the JWT that is
    accessing this endpoint. If no JWT is present,`None` is returned instead.
    """
    return get_raw_jwt().get(config.identity_claim_key, None)


def get_jwt_claims():
    """
    In a protected endpoint, this will return the dictionary of custom claims
    in the JWT that is accessing the endpoint. If no custom user claims are
    present, an empty dict is returned instead.
    """
    return get_raw_jwt().get(config.user_claims_key, {})


def get_current_user():
    """
    In a protected endpoint, this will return the user object for the JWT that
    is accessing this endpoint. This is only present if the
    :meth:`~flask_jwt_extended.JWTManager.user_loader_callback_loader` is
    being used. If the user loader callback is not being used, this will
    return `None`.
    """
    return getattr(ctx_stack.top, 'jwt_user', None)


def get_jti(encoded_token):
    """
    Returns the JTI (unique identifier) of an encoded JWT

    :param encoded_token: The encoded JWT to get the JTI from.
    """
    return decode_token(encoded_token).get('jti')


def decode_token(encoded_token, csrf_value=None):
    """
    Returns the decoded token (python dict) from an encoded JWT. This does all
    the checks to insure that the decoded token is valid before returning it.

    :param encoded_token: The encoded JWT to decode into a python dict.
    :param csrf_value: Expected CSRF double submit value (optional)
    """
    return decode_jwt(
        encoded_token=encoded_token,
        secret=config.decode_key,
        algorithm=config.algorithm,
        identity_claim_key=config.identity_claim_key,
        user_claims_key=config.user_claims_key,
        csrf_value=csrf_value
    )


def _get_jwt_manager():
    try:
        return current_app.extensions['flask-jwt-extended']
    except KeyError:  # pragma: no cover
        raise RuntimeError("You must initialize a JWTManager with this flask "
                           "application before using this method")


def create_access_token(identity, fresh=False, expires_delta=None):
    """
    Create a new access token.

    :param identity: The identity of this token, which can be any data that is
                     json serializable. It can also be a python object, in which
                     case you can use the
                     :meth:`~flask_jwt_extended.JWTManager.user_identity_loader`
                     to define a callback function that will be used to pull a
                     json serializable identity out of the object.
    :param fresh: If this token should be marked as fresh, and can thus access
                  :func:`~flask_jwt_extended.fresh_jwt_required` endpoints.
                  Defaults to `False`. This value can also be a
                  `datetime.timedelta` in which case it will indicate how long
                  this token will be considered fresh.
    :param expires_delta: A `datetime.timedelta` for how long this token should
                          last before it expires. Set to False to disable
                          expiration. If this is None, it will use the
                          'JWT_ACCESS_TOKEN_EXPIRES` config value
                          (see :ref:`Configuration Options`)
    :return: An encoded access token
    """
    jwt_manager = _get_jwt_manager()
    return jwt_manager._create_access_token(identity, fresh, expires_delta)


def create_refresh_token(identity, expires_delta=None):
    """
    Creates a new refresh token.

    :param identity: The identity of this token, which can be any data that is
                     json serializable. It can also be a python object, in which
                     case you can use the
                     :meth:`~flask_jwt_extended.JWTManager.user_identity_loader`
                     to define a callback function that will be used to pull a
                     json serializable identity out of the object.
    :param expires_delta: A `datetime.timedelta` for how long this token should
                          last before it expires. Set to False to disable
                          expiration. If this is None, it will use the
                          'JWT_REFRESH_TOKEN_EXPIRES` config value
                          (see :ref:`Configuration Options`)
    :return: An encoded access token
    """
    jwt_manager = _get_jwt_manager()
    return jwt_manager._create_refresh_token(identity, expires_delta)


def has_user_loader():
    jwt_manager = _get_jwt_manager()
    return jwt_manager._user_loader_callback is not None


def user_loader(*args, **kwargs):
    jwt_manager = _get_jwt_manager()
    return jwt_manager._user_loader_callback(*args, **kwargs)


def has_token_in_blacklist_callback():
    jwt_manager = _get_jwt_manager()
    return jwt_manager._token_in_blacklist_callback is not None


def token_in_blacklist(*args, **kwargs):
    jwt_manager = _get_jwt_manager()
    return jwt_manager._token_in_blacklist_callback(*args, **kwargs)


def verify_token_type(decoded_token, expected_type):
    if decoded_token['type'] != expected_type:
        raise WrongTokenError('Only {} tokens are allowed'.format(expected_type))


def verify_token_not_blacklisted(decoded_token, request_type):
    if not config.blacklist_enabled:
        return
    if not has_token_in_blacklist_callback():
        raise RuntimeError("A token_in_blacklist_callback must be provided via "
                           "the '@token_in_blacklist_loader' if "
                           "JWT_BLACKLIST_ENABLED is True")
    if config.blacklist_access_tokens and request_type == 'access':
        if token_in_blacklist(decoded_token):
            raise RevokedTokenError('Token has been revoked')
    if config.blacklist_refresh_tokens and request_type == 'refresh':
        if token_in_blacklist(decoded_token):
            raise RevokedTokenError('Token has been revoked')


def verify_token_claims(jwt_data):
    jwt_manager = _get_jwt_manager()
    user_claims = jwt_data[config.user_claims_key]
    if not jwt_manager._claims_verification_callback(user_claims):
        raise UserClaimsVerificationError('User claims verification failed')


def get_csrf_token(encoded_token):
    """
    Returns the CSRF double submit token from an encoded JWT.

    :param encoded_token: The encoded JWT
    :return: The CSRF double submit token
    """
    token = decode_token(encoded_token)
    return token['csrf']


def set_access_cookies(response, encoded_access_token, max_age=None):
    """
    Takes a flask response object, and an encoded access token, and configures
    the response to set in the access token in a cookie. If `JWT_CSRF_IN_COOKIES`
    is `True` (see :ref:`Configuration Options`), this will also set the CSRF
    double submit values in a separate cookie.

    :param response: The Flask response object to set the access cookies in.
    :param encoded_access_token: The encoded access token to set in the cookies.
    :param max_age: The max age of the cookie. If this is None, it will use the
                    `JWT_SESSION_COOKIE` option (see :ref:`Configuration Options`).
                    Otherwise, it will use this as the cookies `max-age`.
                    Values should be the number of seconds (as an integer).
    """
    if not config.jwt_in_cookies:
        raise RuntimeWarning("set_access_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    # Set the access JWT in the cookie
    response.set_cookie(config.access_cookie_name,
                        value=encoded_access_token,
                        max_age=max_age or config.cookie_max_age,
                        secure=config.cookie_secure,
                        httponly=True,
                        domain=config.cookie_domain,
                        path=config.access_cookie_path,
                        samesite=config.cookie_samesite)

    # If enabled, set the csrf double submit access cookie
    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(config.access_csrf_cookie_name,
                            value=get_csrf_token(encoded_access_token),
                            max_age=max_age or config.cookie_max_age,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.access_csrf_cookie_path,
                            samesite=config.cookie_samesite)


def set_refresh_cookies(response, encoded_refresh_token, max_age=None):
    """
    Takes a flask response object, and an encoded refresh token, and configures
    the response to set in the refresh token in a cookie. If `JWT_CSRF_IN_COOKIES`
    is `True` (see :ref:`Configuration Options`), this will also set the CSRF
    double submit values in a separate cookie.

    :param response: The Flask response object to set the refresh cookies in.
    :param encoded_refresh_token: The encoded refresh token to set in the cookies.
    :param max_age: The max age of the cookie. If this is None, it will use the
                    `JWT_SESSION_COOKIE` option (see :ref:`Configuration Options`).
                    Otherwise, it will use this as the cookies `max-age`.
                    Values should be the number of seconds (as an integer).
    """
    if not config.jwt_in_cookies:
        raise RuntimeWarning("set_refresh_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    # Set the refresh JWT in the cookie
    response.set_cookie(config.refresh_cookie_name,
                        value=encoded_refresh_token,
                        max_age=max_age or config.cookie_max_age,
                        secure=config.cookie_secure,
                        httponly=True,
                        domain=config.cookie_domain,
                        path=config.refresh_cookie_path,
                        samesite=config.cookie_samesite)

    # If enabled, set the csrf double submit refresh cookie
    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(config.refresh_csrf_cookie_name,
                            value=get_csrf_token(encoded_refresh_token),
                            max_age=max_age or config.cookie_max_age,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.refresh_csrf_cookie_path,
                            samesite=config.cookie_samesite)


def unset_jwt_cookies(response):
    """
    Takes a flask response object, and configures it to unset (delete) JWTs
    stored in cookies.

    :param response: The Flask response object to delete the JWT cookies in.
    """
    if not config.jwt_in_cookies:
        raise RuntimeWarning("unset_refresh_cookies() called without "
                             "'JWT_TOKEN_LOCATION' configured to use cookies")

    response.set_cookie(config.refresh_cookie_name,
                        value='',
                        expires=0,
                        secure=config.cookie_secure,
                        httponly=True,
                        domain=config.cookie_domain,
                        path=config.refresh_cookie_path,
                        samesite=config.cookie_samesite)
    response.set_cookie(config.access_cookie_name,
                        value='',
                        expires=0,
                        secure=config.cookie_secure,
                        httponly=True,
                        domain=config.cookie_domain,
                        path=config.access_cookie_path,
                        samesite=config.cookie_samesite)

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(config.refresh_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.refresh_csrf_cookie_path,
                            samesite=config.cookie_samesite)
        response.set_cookie(config.access_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.access_csrf_cookie_path,
                            samesite=config.cookie_samesite)
