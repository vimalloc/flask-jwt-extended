import datetime

from jwt import ExpiredSignatureError, InvalidTokenError

from flask_jwt_extended.blacklist import store_token
from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import (
    JWTDecodeError, NoAuthorizationError, InvalidHeaderError, WrongTokenError,
    RevokedTokenError, FreshTokenRequired, CSRFError
)
from flask_jwt_extended.default_callbacks import (
    default_expired_token_callback, default_user_claims_callback,
    default_user_identity_callback, default_invalid_token_callback,
    default_unauthorized_callback,
    default_needs_fresh_token_callback,
    default_revoked_token_callback
)
from flask_jwt_extended.tokens import (
    encode_refresh_token, decode_jwt,
    encode_access_token
)


class JWTManager(object):
    def __init__(self, app=None):
        """
        Create the JWTManager instance. You can either pass a flask application
        in directly here to register this extension with the flask app, or
        call init_app after creating this object

        :param app: A flask application
        """
        # Register the default error handler callback methods. These can be
        # overridden with the appropriate loader decorators
        self._user_claims_callback = default_user_claims_callback
        self._user_identity_callback = default_user_identity_callback
        self._expired_token_callback = default_expired_token_callback
        self._invalid_token_callback = default_invalid_token_callback
        self._unauthorized_callback = default_unauthorized_callback
        self._needs_fresh_token_callback = default_needs_fresh_token_callback
        self._revoked_token_callback = default_revoked_token_callback

        # Register this extension with the flask app now (if it is provided)
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Register this extension with the flask app

        :param app: A flask application
        """
        # Save this so we can use it later in the extension
        app.jwt_manager = self

        # Set all the default configurations for this extension
        self._set_default_configuration_options(app)
        self._set_error_handler_callbacks(app)

        # Set propagate exceptions, so all of our error handlers properly
        # work in production
        app.config['PROPAGATE_EXCEPTIONS'] = True

    def _set_error_handler_callbacks(self, app):
        """
        Sets the error handler callbacks used by this extension
        """
        @app.errorhandler(NoAuthorizationError)
        def handle_auth_error(e):
            return self._unauthorized_callback(str(e))

        @app.errorhandler(CSRFError)
        def handle_auth_error(e):
            return self._unauthorized_callback(str(e))

        @app.errorhandler(ExpiredSignatureError)
        def handle_expired_error(e):
            return self._expired_token_callback()

        @app.errorhandler(InvalidHeaderError)
        def handle_invalid_header_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(InvalidTokenError)
        def handle_invalid_token_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(JWTDecodeError)
        def handle_jwt_decode_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(WrongTokenError)
        def handle_wrong_token_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(RevokedTokenError)
        def handle_revoked_token_error(e):
            return self._revoked_token_callback()

        @app.errorhandler(FreshTokenRequired)
        def handle_fresh_token_required(e):
            return self._needs_fresh_token_callback()

    @staticmethod
    def _set_default_configuration_options(app):
        """
        Sets the default configuration options used by this extension
        """
        # Where to look for the JWT. Available options are cookies or headers
        app.config.setdefault('JWT_TOKEN_LOCATION', ['headers'])

        # Options for JWTs when the TOKEN_LOCATION is headers
        app.config.setdefault('JWT_HEADER_NAME', 'Authorization')
        app.config.setdefault('JWT_HEADER_TYPE', 'Bearer')

        # Option for JWTs when the TOKEN_LOCATION is cookies
        app.config.setdefault('JWT_ACCESS_COOKIE_NAME', 'access_token_cookie')
        app.config.setdefault('JWT_REFRESH_COOKIE_NAME', 'refresh_token_cookie')
        app.config.setdefault('JWT_ACCESS_COOKIE_PATH', '/')
        app.config.setdefault('JWT_REFRESH_COOKIE_PATH', '/')
        app.config.setdefault('JWT_COOKIE_SECURE', False)
        app.config.setdefault('JWT_COOKIE_DOMAIN', None)
        app.config.setdefault('JWT_SESSION_COOKIE', True)

        # Options for using double submit csrf protection
        app.config.setdefault('JWT_COOKIE_CSRF_PROTECT', True)
        app.config.setdefault('JWT_CSRF_METHODS', ['POST', 'PUT', 'PATCH', 'DELETE'])
        app.config.setdefault('JWT_ACCESS_CSRF_HEADER_NAME', 'X-CSRF-TOKEN')
        app.config.setdefault('JWT_REFRESH_CSRF_HEADER_NAME', 'X-CSRF-TOKEN')
        app.config.setdefault('JWT_CSRF_IN_COOKIES', True)
        app.config.setdefault('JWT_ACCESS_CSRF_COOKIE_NAME', 'csrf_access_token')
        app.config.setdefault('JWT_REFRESH_CSRF_COOKIE_NAME', 'csrf_refresh_token')
        app.config.setdefault('JWT_ACCESS_CSRF_COOKIE_PATH', '/')
        app.config.setdefault('JWT_REFRESH_CSRF_COOKIE_PATH', '/')

        # How long an a token will live before they expire.
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES', datetime.timedelta(minutes=15))
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES', datetime.timedelta(days=30))

        # What algorithm to use to sign the token. See here for a list of options:
        # https://github.com/jpadilla/pyjwt/blob/master/jwt/api_jwt.py
        app.config.setdefault('JWT_ALGORITHM', 'HS256')

        # Secret key to sign JWTs with. Only used if a symmetric algorithm is
        # used (such as the HS* algorithms). We will use the app secret key
        # if this is not set.
        app.config.setdefault('JWT_SECRET_KEY', None)

        # Keys to sign JWTs with when use when using an asymmetric
        # (public/private key) algorithm, such as RS* or EC*
        app.config.setdefault('JWT_PRIVATE_KEY', None)
        app.config.setdefault('JWT_PUBLIC_KEY', None)

        # Options for blacklisting/revoking tokens
        app.config.setdefault('JWT_BLACKLIST_ENABLED', False)
        app.config.setdefault('JWT_BLACKLIST_STORE', None)
        app.config.setdefault('JWT_BLACKLIST_TOKEN_CHECKS', 'refresh')

    def user_claims_loader(self, callback):
        """
        This sets the callback method for adding custom user claims to a JWT.

        By default, no extra user claims will be added to the JWT.

        Callback must be a function that takes only one argument, which is the
        identity of the JWT being created.
        """
        self._user_claims_callback = callback
        return callback

    def user_identity_loader(self, callback):
        """
        This sets the callback method for adding custom user claims to a JWT.

        By default, no extra user claims will be added to the JWT.

        Callback must be a function that takes only one argument, which is the
        identity of the JWT being created.
        """
        self._user_identity_callback = callback
        return callback

    def expired_token_loader(self, callback):
        """
        Sets the callback method to be called if an expired JWT is received

        The default implementation will return json '{"msg": "Token has expired"}'
        with a 401 status code.

        Callback must be a function that takes zero arguments.
        """
        self._expired_token_callback = callback
        return callback

    def invalid_token_loader(self, callback):
        """
        Sets the callback method to be called if an invalid JWT is received.

        The default implementation will return json '{"msg": <err>}' with a 401
        status code.

        Callback must be a function that takes only one argument, which is the
        error message of why the token is invalid.
        """
        self._invalid_token_callback = callback
        return callback

    def unauthorized_loader(self, callback):
        """
        Sets the callback method to be called if an invalid JWT is received

        The default implementation will return '{"msg": "Missing Authorization Header"}'
        json with a 401 status code.

        Callback must be a function that takes only one argument, which is the
        error message of why the token is invalid.
        """
        self._unauthorized_callback = callback
        return callback

    def needs_fresh_token_loader(self, callback):
        """
        Sets the callback method to be called if a valid and non-fresh token
        attempts to access an endpoint protected with @fresh_jwt_required.

        The default implementation will return json '{"msg": "Fresh token required"}'
        with a 401 status code.

        Callback must be a function that takes no arguments.
        """
        self._needs_fresh_token_callback = callback
        return callback

    def revoked_token_loader(self, callback):
        """
        Sets the callback method to be called if a blacklisted (revoked) token
        attempt to access a protected endpoint

        The default implementation will return json '{"msg": "Token has been revoked"}'
        with a 401 status code.

        Callback must be a function that takes no arguments.
        """
        self._revoked_token_callback = callback
        return callback

    def create_refresh_token(self, identity, expires_delta=None):
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
        if expires_delta is None:
            expires_delta = config.refresh_expires

        refresh_token = encode_refresh_token(
            identity=self._user_identity_callback(identity),
            secret=config.encode_key,
            algorithm=config.algorithm,
            expires_delta=expires_delta,
            csrf=config.csrf_protect
        )

        # If blacklisting is enabled, store this token in our key-value store
        if config.blacklist_enabled:
            decoded_token = decode_jwt(refresh_token, config.decode_key,
                                       config.algorithm, csrf=config.csrf_protect)
            store_token(decoded_token, revoked=False)
        return refresh_token

    def create_access_token(self, identity, fresh=False, expires_delta=None):
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
        if expires_delta is None:
            expires_delta = config.access_expires

        access_token = encode_access_token(
            identity=self._user_identity_callback(identity),
            secret=config.encode_key,
            algorithm=config.algorithm,
            expires_delta=expires_delta,
            fresh=fresh,
            user_claims=self._user_claims_callback(identity),
            csrf=config.csrf_protect
        )
        if config.blacklist_enabled and config.blacklist_access_tokens:
            decoded_token = decode_jwt(access_token, config.decode_key,
                                       config.algorithm, csrf=config.csrf_protect)
            store_token(decoded_token, revoked=False)
        return access_token
