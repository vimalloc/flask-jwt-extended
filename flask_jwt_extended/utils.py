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
    return get_raw_jwt().get(config.identity_claim, None)


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
    """
    return decode_token(encoded_token).get('jti')


def decode_token(encoded_token):
    """
    Returns the decoded token from an encoded one. This does all the checks
    to insure that the decoded token is valid before returning it.
    """
    return decode_jwt(
        encoded_token=encoded_token,
        secret=config.decode_key,
        algorithm=config.algorithm,
        csrf=config.csrf_protect,
        identity_claim=config.identity_claim
    )


def _get_jwt_manager():
    try:
        return current_app.jwt_manager
    except AttributeError:  # pragma: no cover
        raise RuntimeError("You must initialize a JWTManager with this flask "
                           "application before using this method")


def create_access_token(identity, fresh=False, expires_delta=None):
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
    :param expires_delta: A datetime.timedelta for how long this token should
                          last before it expires. If this is None, it will
                          use the 'JWT_ACCESS_TOKEN_EXPIRES` config value
    :return: A new access token
    """

    jwt_manager = _get_jwt_manager()
    return jwt_manager._create_access_token(identity, fresh, expires_delta)


def create_refresh_token(identity, expires_delta=None):
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
    :param expires_delta: A datetime.timedelta for how long this token should
                          last before it expires. If this is None, it will
                          use the 'JWT_REFRESH_TOKEN_EXPIRES` config value
    :return: A new refresh token
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


def verify_token_claims(*args, **kwargs):
    jwt_manager = _get_jwt_manager()
    return jwt_manager._claims_verification_callback(*args, **kwargs)


def get_csrf_token(encoded_token):
    token = decode_jwt(
        encoded_token,
        config.decode_key,
        config.algorithm,
        csrf=True,
        identity_claim=config.identity_claim
    )
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
