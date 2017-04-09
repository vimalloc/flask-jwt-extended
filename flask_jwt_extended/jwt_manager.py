import datetime

from flask import jsonify
from jwt import ExpiredSignatureError, InvalidTokenError

from flask_jwt_extended.exceptions import JWTDecodeError, NoAuthorizationError, \
    InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired, \
    CSRFError


class JWTManager:
    def __init__(self, app=None):
        # Function that will be called to add custom user claims to a JWT.
        self._user_claims_callback = lambda _: {}

        # Function that will be called to return an identity from an object
        self._user_identity_callback = lambda i: i

        # Function that will be called when an expired token is received
        self._expired_token_callback = lambda: (
            jsonify({'msg': 'Token has expired'}), 401
        )

        # Function that will be called when an invalid token is received
        self._invalid_token_callback = lambda err: (
            jsonify({'msg': err}), 422
        )

        # Function that will be called when attempting to access a protected
        # endpoint without a valid token
        self._unauthorized_callback = lambda err: (
            jsonify({'msg': err}), 401
        )

        # Function that will be called when attempting to access a fresh_jwt_required
        # endpoint with a valid token that is not fresh
        self._needs_fresh_token_callback = lambda: (
            jsonify({'msg': 'Fresh token required'}), 401
        )

        # Function that will be called when a revoked token attempts to access
        # a protected endpoint
        self._revoked_token_callback = lambda: (
            jsonify({'msg': 'Token has been revoked'}), 401
        )

        # Setup the app if it is given (can be passed to this constructor, or
        # called later by calling init_app directly)
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Register this extension with the flask app
        """
        # Save this so we can use it later in the extension
        app.jwt_manager = self

        # Set propagate exceptions, so all of these error handlers properly
        # work in production
        app.config['PROPAGATE_EXCEPTIONS'] = True

        self._set_default_configuration_options(app)
        self._set_error_handler_callbacks(app)

    def _set_error_handler_callbacks(self, app):
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

    def _set_default_configuration_options(self, app):
        # Where to look for the JWT. Available options are cookies or headers
        app.config.setdefault('JWT_TOKEN_LOCATION', ['headers'])

        # Options for JWTs when the TOKEN_LOCATION is headers
        app.config.setdefault('JWT_ACCESS_HEADER_NAME', 'Authorization')
        app.config.setdefault('JWT_REFRESH_HEADER_NAME', 'Authorization')
        app.config.setdefault('JWT_HEADER_TYPE', 'Bearer')

        # Option for JWTs when the TOKEN_LOCATION is cookies
        app.config.setdefault('JWT_ACCESS_COOKIE_NAME', 'access_token_cookie')
        app.config.setdefault('JWT_REFRESH_COOKIE_NAME', 'refresh_token_cookie')
        app.config.setdefault('JWT_ACCESS_COOKIE_PATH', '/')
        app.config.setdefault('JWT_REFRESH_COOKIE_PATH', '/')
        app.config.setdefault('JWT_COOKIE_SECURE', False)
        app.config.setdefault('JWT_SESSION_COOKIE', True)

        # Options for using double submit csrf protection
        app.config.setdefault('JWT_COOKIE_CSRF_PROTECT', True)
        app.config.setdefault('JWT_CSRF_METHODS', ['POST', 'PUT', 'PATCH', 'DELETE'])
        app.config.setdefault('JWT_ACCESS_CSRF_COOKIE_NAME', 'csrf_access_token')
        app.config.setdefault('JWT_REFRESH_CSRF_COOKIE_NAME', 'csrf_refresh_token')
        app.config.setdefault('JWT_ACCESS_CSRF_HEADER_NAME', 'X-CSRF-TOKEN')
        app.config.setdefault('JWT_REFRESH_CSRF_HEADER_NAME', 'X-CSRF-TOKEN')

        # How long an a token will live before they expire.
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES', datetime.timedelta(minutes=15))
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES', datetime.timedelta(days=30))

        # What algorithm to use to sign the token. See here for a list of options:
        # https://github.com/jpadilla/pyjwt/blob/master/jwt/api_jwt.py (note that
        # public private key is not yet supported)
        app.config.setdefault('JWT_ALGORITHM', 'HS256')

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
