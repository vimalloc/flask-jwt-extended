from flask import current_app

from flask_jwt_extended.exceptions import RevokedTokenError
from flask_jwt_extended.exceptions import UserClaimsVerificationError
from flask_jwt_extended.exceptions import WrongTokenError


def get_jwt_manager():
    try:
        return current_app.extensions["flask-jwt-extended"]
    except KeyError:  # pragma: no cover
        raise RuntimeError(
            "You must initialize a JWTManager with this flask "
            "application before using this method"
        )


def has_user_lookup():
    jwt_manager = get_jwt_manager()
    return jwt_manager._user_lookup_callback is not None


def user_lookup(*args, **kwargs):
    jwt_manager = get_jwt_manager()
    return jwt_manager._user_lookup_callback(*args, **kwargs)


def verify_token_type(decoded_token, expected_type):
    if decoded_token["type"] != expected_type:
        raise WrongTokenError("Only {} tokens are allowed".format(expected_type))


def verify_token_not_blocklisted(jwt_header, jwt_data, request_type):
    jwt_manager = get_jwt_manager()
    if jwt_manager._token_in_blocklist_callback(jwt_header, jwt_data):
        raise RevokedTokenError(jwt_header, jwt_data)


def custom_verification_for_token(jwt_header, jwt_data):
    jwt_manager = get_jwt_manager()
    if not jwt_manager._token_verification_callback(jwt_header, jwt_data):
        error_msg = "User claims verification failed"
        raise UserClaimsVerificationError(error_msg, jwt_header, jwt_data)
