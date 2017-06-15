from flask import current_app
from werkzeug.local import LocalProxy

try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

from flask_jwt_extended.config import config
from flask_jwt_extended.tokens import decode_jwt


# Proxy to access the current user
current_user = LocalProxy(lambda: get_current_user())


def get_raw_jwt():
    """
    Returns the python dictionary which has all of the data in this JWT. If no
    JWT is currently present, and empty dict is returned
    """
    return getattr(ctx_stack.top, 'jwt', {})


def get_jwt_identity():
    """
    Returns the identity of the JWT in this context. If no JWT is present,
    None is returned.
    """
    return get_raw_jwt().get('identity', None)


def get_jwt_claims():
    """
    Returns the dictionary of custom use claims in this JWT. If no custom user
    claims are present, an empty dict is returned
    """
    return get_raw_jwt().get('user_claims', {})


def get_current_user():
    """
    Returns the loaded user from a user_loader callback in a protected endpoint.
    If no user was loaded, or if no user_loader callback was defined, this will
    return None
    """
    return getattr(ctx_stack.top, 'jwt_user', None)


def get_jti(encoded_token):
    """
    Returns the JTI given the JWT encoded token

    :param encoded_token: The encoded JWT string
    :return: The JTI of the token
    """
    return decode_jwt(encoded_token, config.secret_key, config.algorithm, config.csrf_protect).get('jti')


def _get_jwt_manager():
    try:
        return current_app.jwt_manager
    except AttributeError:  # pragma: no cover
        raise RuntimeError("You must initialize a JWTManager with this flask"
                           "application before using this method")


def create_access_token(*args, **kwargs):
    jwt_manager = _get_jwt_manager()
    return jwt_manager.create_access_token(*args, **kwargs)


def create_refresh_token(*args, **kwargs):
    jwt_manager = _get_jwt_manager()
    return jwt_manager.create_refresh_token(*args, **kwargs)


def user_loader(*args, **kwargs):
    jwt_manager = _get_jwt_manager()
    return jwt_manager.user_loader(*args, **kwargs)


def has_user_loader(*args, **kwargs):
    jwt_manager = _get_jwt_manager()
    return jwt_manager.has_user_loader(*args, **kwargs)


def get_csrf_token(encoded_token):
    token = decode_jwt(encoded_token, config.decode_key, config.algorithm, csrf=True)
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
                        max_age=config.cookie_max_age,
                        secure=config.cookie_secure,
                        httponly=True,
                        domain=config.cookie_domain,
                        path=config.access_cookie_path)

    # If enabled, set the csrf double submit access cookie
    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(config.access_csrf_cookie_name,
                            value=get_csrf_token(encoded_access_token),
                            max_age=config.cookie_max_age,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.access_csrf_cookie_path)


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
                        max_age=config.cookie_max_age,
                        secure=config.cookie_secure,
                        httponly=True,
                        domain=config.cookie_domain,
                        path=config.refresh_cookie_path)

    # If enabled, set the csrf double submit refresh cookie
    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(config.refresh_csrf_cookie_name,
                            value=get_csrf_token(encoded_refresh_token),
                            max_age=config.cookie_max_age,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.refresh_csrf_cookie_path)


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
                        domain=config.cookie_domain,
                        path=config.refresh_cookie_path)
    response.set_cookie(config.access_cookie_name,
                        value='',
                        expires=0,
                        secure=config.cookie_secure,
                        httponly=True,
                        domain=config.cookie_domain,
                        path=config.access_cookie_path)

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(config.refresh_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.refresh_csrf_cookie_path)
        response.set_cookie(config.access_csrf_cookie_name,
                            value='',
                            expires=0,
                            secure=config.cookie_secure,
                            httponly=False,
                            domain=config.cookie_domain,
                            path=config.access_csrf_cookie_path)
