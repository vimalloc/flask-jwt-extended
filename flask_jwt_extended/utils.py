from flask import current_app
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as ctx_stack

from flask_jwt_extended.blacklist import store_token
from flask_jwt_extended.config import config
from flask_jwt_extended.tokens import (
    decode_jwt, encode_refresh_token, encode_access_token
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


def get_csrf_token(encoded_token):
    token = decode_jwt(encoded_token, config.secret_key, config.algorithm, csrf=True)
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
                        path=config.access_cookie_path)

    # If enabled, set the csrf double submit access cookie
    if config.csrf_protect:
        response.set_cookie(config.access_csrf_cookie_name,
                            value=get_csrf_token(encoded_access_token),
                            max_age=config.cookie_max_age,
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
                        max_age=config.cookie_max_age,
                        secure=config.cookie_secure,
                        httponly=True,
                        path=config.refresh_cookie_path)

    # If enabled, set the csrf double submit refresh cookie
    if config.csrf_protect:
        response.set_cookie(config.refresh_csrf_cookie_name,
                            value=get_csrf_token(encoded_refresh_token),
                            max_age=config.cookie_max_age,
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
