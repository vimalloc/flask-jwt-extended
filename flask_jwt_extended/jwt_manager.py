from flask import jsonify

from flask_jwt_extended.exceptions import JWTDecodeError, NoAuthorizationError, \
    InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired
from jwt import ExpiredSignatureError, InvalidTokenError


class JWTManager:
    def __init__(self, app=None):
        # Function that will be called to add custom user claims to a JWT.
        self.user_claims_callback = lambda _: {}

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
        self._unauthorized_callback = lambda: (
            jsonify({'msg': 'Missing Authorization Header'}), 401
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

        # Setup the app if it is given (can be passed to this consturctor, or
        # called later by calling init_app directly)
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Register this extension with the flask app
        """
        app.jwt_manager = self

        @app.errorhandler(NoAuthorizationError)
        def handle_auth_error(e):
            return self._unauthorized_callback()

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
        def hanlde_revoked_token_error(e):
            return self._revoked_token_callback()

        @app.errorhandler(FreshTokenRequired)
        def handle_fresh_token_required(e):
            return self._needs_fresh_token_callback()

    def user_claims_loader(self, callback):
        """
        This sets the callback method for adding custom user claims to a JWT.

        By default, no extra user claims will be added to the JWT.

        Callback must be a function that takes only one argument, which is the
        identity of the JWT being created.
        """
        self.user_claims_callback = callback
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
