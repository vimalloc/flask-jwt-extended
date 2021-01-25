import jwt
from flask import _request_ctx_stack
from werkzeug.local import LocalProxy

from flask_jwt_extended.config import config
from flask_jwt_extended.internal_utils import get_jwt_manager


# Proxy to access the current user
current_user = LocalProxy(lambda: get_current_user())


def get_jwt():
    """
    In a protected endpoint, this will return the python dictionary which has
    the payload of the JWT that is accessing the endpoint. If no JWT is present
    due to `jwt_required(optional=True)`, an empty dictionary is returned.

    :return:
        The payload (claims) of the JWT in the current request
    """
    decoded_jwt = getattr(_request_ctx_stack.top, "jwt", None)
    if decoded_jwt is None:
        raise RuntimeError(
            "You must call `@jwt_required()` or `verify_jwt_in_request` "
            "before using this method"
        )
    return decoded_jwt


def get_jwt_header():
    """
    In a protected endpoint, this will return the python dictionary which has
    the header of the JWT that is accessing the endpoint. If no JWT is present
    due to `jwt_required(optional=True)`, an empty dictionary is returned.

    :return:
        The headers of the JWT in the current request
    """
    decoded_header = getattr(_request_ctx_stack.top, "jwt_header", None)
    if decoded_header is None:
        raise RuntimeError(
            "You must call `@jwt_required()` or `verify_jwt_in_request` "
            "before using this method"
        )
    return decoded_header


def get_jwt_identity():
    """
    In a protected endpoint, this will return the identity of the JWT that is
    accessing the endpoint. If no JWT is present due to
    `jwt_required(optional=True)`, `None` is returned.

    :return:
        The identity of the JWT in the current request
    """
    return get_jwt().get(config.identity_claim_key, None)


def get_current_user():
    """
    In a protected endpoint, this will return the user object for the JWT that
    is accessing the endpoint.

    This is only usable if :meth:`~flask_jwt_extended.JWTManager.user_lookup_loader`
    is configured. If the user loader callback is not being used, this will
    raise an error.

    If no JWT is present due to `jwt_required(optional=True)`, `None` is returned.

    :return:
        The current user object for the JWT in the current request
    """
    jwt_user_dict = getattr(_request_ctx_stack.top, "jwt_user", None)
    if jwt_user_dict is None:
        raise RuntimeError(
            "You must provide a `@jwt.user_lookup_loader` callback to use "
            "this method"
        )
    return jwt_user_dict["loaded_user"]


def decode_token(encoded_token, csrf_value=None, allow_expired=False):
    """
    Returns the decoded token (python dict) from an encoded JWT. This does all
    the checks to insure that the decoded token is valid before returning it.

    This will not fire the user loader callbacks, save the token for access
    in protected endpoints, checked if a token is revoked, etc. This is puerly
    used to insure that a JWT is valid.

    :param encoded_token:
        The encoded JWT to decode.

    :param csrf_value:
        Expected CSRF double submit value (optional).

    :param allow_expired:
        If `True`, do not raise an error if the JWT is expired.  Defaults to `False`

    :return:
        Dictionary containing the payload of the JWT decoded JWT.
    """
    jwt_manager = get_jwt_manager()
    return jwt_manager._decode_jwt_from_config(encoded_token, csrf_value, allow_expired)


def create_access_token(
    identity,
    fresh=False,
    expires_delta=None,
    additional_claims=None,
    additional_headers=None,
):
    """
    Create a new access token.

    :param identity:
        The identity of this token. It can be any data that is json serializable.
        You can use :meth:`~flask_jwt_extended.JWTManager.user_identity_loader`
        to define a callback function to convert any object passed in into a json
        serializable format.

    :param fresh:
        If this token should be marked as fresh, and can thus access endpoints
        protected with `@jwt_required(fresh=True)`. Defaults to `False`.

        This value can also be a `datetime.timedelta`, which indicate
        how long this token will be considered fresh.

    :param expires_delta:
        A `datetime.timedelta` for how long this token should last before it
        expires. Set to False to disable expiration. If this is None, it will use
        the 'JWT_ACCESS_TOKEN_EXPIRES` config value (see :ref:`Configuration Options`)

    :param additional_claims:
        Optional. A hash of claims to include in the access token.  These claims are
        merged into the default claims (exp, iat, etc) and claims returned from the
        :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader` callback.
        On conflict, these claims take presidence.

    :param headers:
        Optional. A hash of headers to include in the access token. These headers
        are merged into the default headers (alg, typ) and headers returned from
        the :meth:`~flask_jwt_extended.JWTManager.additional_headers_loader`
        callback. On conflict, these headers take presidence.

    :return:
        An encoded access token
    """
    jwt_manager = get_jwt_manager()
    return jwt_manager._encode_jwt_from_config(
        claims=additional_claims,
        expires_delta=expires_delta,
        fresh=fresh,
        headers=additional_headers,
        identity=identity,
        token_type="access",
    )


def create_refresh_token(
    identity, expires_delta=None, additional_claims=None, additional_headers=None
):
    """
    Create a new refresh token.

    :param identity:
        The identity of this token. It can be any data that is json serializable.
        You can use :meth:`~flask_jwt_extended.JWTManager.user_identity_loader`
        to define a callback function to convert any object passed in into a json
        serializable format.

    :param expires_delta:
        A `datetime.timedelta` for how long this token should last before it expires.
        Set to False to disable expiration. If this is None, it will use the
        'JWT_REFRESH_TOKEN_EXPIRES` config value (see :ref:`Configuration Options`)

    :param additional_claims:
        Optional. A hash of claims to include in the refresh token. These claims are
        merged into the default claims (exp, iat, etc) and claims returned from the
        :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader` callback.
        On conflict, these claims take presidence.

    :param headers:
        Optional. A hash of headers to include in the refresh token. These headers
        are merged into the default headers (alg, typ) and headers returned from the
        :meth:`~flask_jwt_extended.JWTManager.additional_headers_loader` callback.
        On conflict, these headers take presidence.

    :return:
        An encoded refresh token
    """
    jwt_manager = get_jwt_manager()
    return jwt_manager._encode_jwt_from_config(
        claims=additional_claims,
        expires_delta=expires_delta,
        fresh=False,
        headers=additional_headers,
        identity=identity,
        token_type="refresh",
    )


def get_unverified_jwt_headers(encoded_token):
    """
    Returns the Headers of an encoded JWT without verifying the signature of the JWT.

    :param encoded_token:
        The encoded JWT to get the Header from.

    :return:
        JWT header parameters as python dict()
    """
    return jwt.get_unverified_header(encoded_token)


def get_jti(encoded_token):
    """
    Returns the JTI (unique identifier) of an encoded JWT

    :param encoded_token:
        The encoded JWT to get the JTI from.

    :return:
        The JTI (unique identifier) of a JWT.
    """
    return decode_token(encoded_token).get("jti")


def get_csrf_token(encoded_token):
    """
    Returns the CSRF double submit token from an encoded JWT.

    :param encoded_token:
        The encoded JWT

    :return:
        The CSRF double submit token (string)
    """
    token = decode_token(encoded_token)
    return token["csrf"]


def set_access_cookies(response, encoded_access_token, max_age=None):
    """
    Modifiy a Flask Response to set a cookie containing the access JWT.
    Also sets the corresponding CSRF cookies if `JWT_CSRF_IN_COOKIES` is `True`
    (see :ref:`Configuration Options`)

    :param response:
        A Flask Response object.

    :param encoded_access_token:
        The encoded access token to set in the cookies.

    :param max_age:
        The max age of the cookie. If this is None, it will use the
        `JWT_SESSION_COOKIE` option (see :ref:`Configuration Options`). Otherwise,
        it will use this as the cookies `max-age` and the JWT_SESSION_COOKIE option
        will be ignored. Values should be the number of seconds (as an integer).
    """
    response.set_cookie(
        config.access_cookie_name,
        value=encoded_access_token,
        max_age=max_age or config.cookie_max_age,
        secure=config.cookie_secure,
        httponly=True,
        domain=config.cookie_domain,
        path=config.access_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(
            config.access_csrf_cookie_name,
            value=get_csrf_token(encoded_access_token),
            max_age=max_age or config.cookie_max_age,
            secure=config.cookie_secure,
            httponly=False,
            domain=config.cookie_domain,
            path=config.access_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )


def set_refresh_cookies(response, encoded_refresh_token, max_age=None):
    """
    Modifiy a Flask Response to set a cookie containing the refresh JWT.
    Also sets the corresponding CSRF cookies if `JWT_CSRF_IN_COOKIES` is `True`
    (see :ref:`Configuration Options`)

    :param response:
        A Flask Response object.

    :param encoded_refresh_token:
        The encoded refresh token to set in the cookies.

    :param max_age:
        The max age of the cookie. If this is None, it will use the
        `JWT_SESSION_COOKIE` option (see :ref:`Configuration Options`). Otherwise,
        it will use this as the cookies `max-age` and the JWT_SESSION_COOKIE option
        will be ignored. Values should be the number of seconds (as an integer).
    """
    response.set_cookie(
        config.refresh_cookie_name,
        value=encoded_refresh_token,
        max_age=max_age or config.cookie_max_age,
        secure=config.cookie_secure,
        httponly=True,
        domain=config.cookie_domain,
        path=config.refresh_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(
            config.refresh_csrf_cookie_name,
            value=get_csrf_token(encoded_refresh_token),
            max_age=max_age or config.cookie_max_age,
            secure=config.cookie_secure,
            httponly=False,
            domain=config.cookie_domain,
            path=config.refresh_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )


def unset_jwt_cookies(response):
    """
    Modifiy a Flask Response to delete the cookies containing access or refresh
    JWTs.  Also deletes the corresponding CSRF cookies if applicable.

    :param response:
        A Flask Response object
    """
    unset_access_cookies(response)
    unset_refresh_cookies(response)


def unset_access_cookies(response):
    """
    Modifiy a Flask Response to delete the cookie containing a refresh JWT.
    Also deletes the corresponding CSRF cookie if applicable.

    :param response:
        A Flask Response object
    """
    response.set_cookie(
        config.access_cookie_name,
        value="",
        expires=0,
        secure=config.cookie_secure,
        httponly=True,
        domain=config.cookie_domain,
        path=config.access_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(
            config.access_csrf_cookie_name,
            value="",
            expires=0,
            secure=config.cookie_secure,
            httponly=False,
            domain=config.cookie_domain,
            path=config.access_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )


def unset_refresh_cookies(response):
    """
    Modifiy a Flask Response to delete the cookie containing an access JWT.
    Also deletes the corresponding CSRF cookie if applicable.

    :param response:
        A Flask Response object
    """
    response.set_cookie(
        config.refresh_cookie_name,
        value="",
        expires=0,
        secure=config.cookie_secure,
        httponly=True,
        domain=config.cookie_domain,
        path=config.refresh_cookie_path,
        samesite=config.cookie_samesite,
    )

    if config.csrf_protect and config.csrf_in_cookies:
        response.set_cookie(
            config.refresh_csrf_cookie_name,
            value="",
            expires=0,
            secure=config.cookie_secure,
            httponly=False,
            domain=config.cookie_domain,
            path=config.refresh_csrf_cookie_path,
            samesite=config.cookie_samesite,
        )
