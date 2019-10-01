"""
These are the default methods implementations that are used in this extension.
All of these can be updated on an app by app basis using the JWTManager
loader decorators. For further information, check out the following links:

http://flask-jwt-extended.readthedocs.io/en/latest/changing_default_behavior.html
http://flask-jwt-extended.readthedocs.io/en/latest/tokens_from_complex_object.html
"""
from flask import jsonify

from flask_jwt_extended.config import config


def default_user_claims_callback(userdata):
    """
    By default, we add no additional claims to the access tokens.

    :param userdata: data passed in as the ```identity``` argument to the
                     ```create_access_token``` and ```create_refresh_token```
                     functions
    """
    return {}


def default_jwt_headers_callback(default_headers):
    """
    By default header typically consists of two parts: the type of the token,
    which is JWT, and the signing algorithm being used, such as HMAC SHA256
    or RSA. But we don't set the default header here we set it as empty which
    further by default set while encoding the token
    :return: default we set None here
    """
    return None


def default_user_identity_callback(userdata):
    """
    By default, we use the passed in object directly as the jwt identity.
    See this for additional info:

    :param userdata: data passed in as the ```identity``` argument to the
                     ```create_access_token``` and ```create_refresh_token```
                     functions
    """
    return userdata


def default_expired_token_callback(expired_token):
    """
    By default, if an expired token attempts to access a protected endpoint,
    we return a generic error message with a 401 status
    """
    return jsonify({config.error_msg_key: 'Token has expired'}), 401


def default_invalid_token_callback(error_string):
    """
    By default, if an invalid token attempts to access a protected endpoint, we
    return the error string for why it is not valid with a 422 status code

    :param error_string: String indicating why the token is invalid
    """
    return jsonify({config.error_msg_key: error_string}), 422


def default_unauthorized_callback(error_string):
    """
    By default, if a protected endpoint is accessed without a JWT, we return
    the error string indicating why this is unauthorized, with a 401 status code

    :param error_string: String indicating why this request is unauthorized
    """
    return jsonify({config.error_msg_key: error_string}), 401


def default_needs_fresh_token_callback():
    """
    By default, if a non-fresh jwt is used to access a ```fresh_jwt_required```
    endpoint, we return a general error message with a 401 status code
    """
    return jsonify({config.error_msg_key: 'Fresh token required'}), 401


def default_revoked_token_callback():
    """
    By default, if a revoked token is used to access a protected endpoint, we
    return a general error message with a 401 status code
    """
    return jsonify({config.error_msg_key: 'Token has been revoked'}), 401


def default_user_loader_error_callback(identity):
    """
    By default, if a user_loader callback is defined and the callback
    function returns None, we return a general error message with a 401
    status code
    """
    result = {config.error_msg_key: "Error loading the user {}".format(identity)}
    return jsonify(result), 401


def default_claims_verification_callback(user_claims):
    """
    By default, we do not do any verification of the user claims.
    """
    return True


def default_verify_claims_failed_callback():
    """
    By default, if the user claims verification failed, we return a generic
    error message with a 400 status code
    """
    return jsonify({config.error_msg_key: 'User claims verification failed'}), 400


def default_decode_key_callback(claims, headers):
    """
    By default, the decode key specified via the JWT_SECRET_KEY or
    JWT_PUBLIC_KEY settings will be used to decode all tokens
    """
    return config.decode_key


def default_encode_key_callback(identity):
    """
    By default, the encode key specified via the JWT_SECRET_KEY or
    JWT_PRIVATE_KEY settings will be used to encode all tokens
    """
    return config.encode_key
