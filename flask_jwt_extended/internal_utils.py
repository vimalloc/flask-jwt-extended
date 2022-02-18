from typing import Any

from flask import current_app

from flask_jwt_extended import JWTManager
from flask_jwt_extended.exceptions import RevokedTokenError
from flask_jwt_extended.exceptions import UserClaimsVerificationError
from flask_jwt_extended.exceptions import WrongTokenError


def get_jwt_manager() -> JWTManager:
    try:
        return current_app.extensions["flask-jwt-extended"]
    except KeyError:  # pragma: no cover
        raise RuntimeError(
            "You must initialize a JWTManager with this flask "
            "application before using this method"
        ) from None


def has_user_lookup() -> bool:
    jwt_manager = get_jwt_manager()
    return jwt_manager._user_lookup_callback is not None


def user_lookup(*args, **kwargs) -> Any:
    jwt_manager = get_jwt_manager()
    return jwt_manager._user_lookup_callback and jwt_manager._user_lookup_callback(
        *args, **kwargs
    )


def verify_token_type(decoded_token: dict, refresh: bool) -> None:
    if not refresh and decoded_token["type"] == "refresh":
        raise WrongTokenError("Only non-refresh tokens are allowed")
    elif refresh and decoded_token["type"] != "refresh":
        raise WrongTokenError("Only refresh tokens are allowed")


def verify_token_not_blocklisted(jwt_header: dict, jwt_data: dict) -> None:
    jwt_manager = get_jwt_manager()
    if jwt_manager._token_in_blocklist_callback(jwt_header, jwt_data):
        raise RevokedTokenError(jwt_header, jwt_data)


def custom_verification_for_token(jwt_header: dict, jwt_data: dict) -> None:
    jwt_manager = get_jwt_manager()
    if not jwt_manager._token_verification_callback(jwt_header, jwt_data):
        error_msg = "User claims verification failed"
        raise UserClaimsVerificationError(error_msg, jwt_header, jwt_data)
