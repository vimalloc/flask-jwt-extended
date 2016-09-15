import uuid
import datetime

import json

from functools import wraps

import jwt
from werkzeug.local import LocalProxy
from flask import Flask, request, jsonify

# TODO read this whole page
# Per http://flask.pocoo.org/docs/0.11/extensiondev/
#
# Find the stack on which we want to store the database connection.
# Starting with Flask 0.9, the _app_ctx_stack is the correct one,
# before that we need to use the _request_ctx_stack.
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:
    from flask import _request_ctx_stack as ctx_stack


# TODO callback method for jwt_required failed (See
#      https://github.com/maxcountryman/flask-login/blob/master/flask_login/utils.py#L221)

class JWTManager:

    def __init__(self, app=None):
        # Function that will be called to get the identity of a JWT
        # TODO think I can delete this, and just pass identity to helper
        self.identity_callback = None

        # Function that will be called to add custom user claims to a JWT
        self.user_claims_callback = None

        self.unauthorized_callback = None
        self.jwt_expired_callback = None
        self.jwt_needs_refresh_callback = None

        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        # In here is where get information stored in the apps config
        app.jwt_manager = self

    def identity_loader(self, callback):
        """
        This sets the callback method for setting the identity of a JWT when it
        is created.

        Callback must be a function that takes only one argument, which is the
        username of the user which just authorized to make a JWT

        :param callback: The callback function for setting a JWT identity
        """
        self.identity_callback = callback
        return callback

    def user_claims_loader(self, callback):
        """
        This sets the callback method for adding custom user claims to a JWT.

        Callback must be a function that takes only one argument, which is the
        identity of the JWT being created.

        :param callback:  The callback function for setting custom user claims
        """
        self.user_claims_callback = callback
        return callback


