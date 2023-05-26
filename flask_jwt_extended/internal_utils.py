import json
from typing import Any
from typing import Type
from typing import TYPE_CHECKING

from flask import current_app
from flask import Flask

from flask_jwt_extended.exceptions import RevokedTokenError
from flask_jwt_extended.exceptions import UserClaimsVerificationError
from flask_jwt_extended.exceptions import WrongTokenError

try:
    from flask.json.provider import DefaultJSONProvider

    HAS_JSON_PROVIDER = True
except ModuleNotFoundError:  # pragma: no cover
    # The flask.json.provider module was added in Flask 2.2.
    # Further details are handled in get_json_encoder.
    HAS_JSON_PROVIDER = False


if TYPE_CHECKING:  # pragma: no cover
    from flask_jwt_extended import JWTManager


def get_jwt_manager() -> "JWTManager":
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


class JSONEncoder(json.JSONEncoder):
    """A JSON encoder which uses the app.json_provider_class for the default"""

    def default(self, o: Any) -> Any:
        # If the registered JSON provider does not implement a default classmethod
        # use the method defined by the DefaultJSONProvider
        default = getattr(
            current_app.json_provider_class, "default", DefaultJSONProvider.default
        )
        return default(o)


def get_json_encoder(app: Flask) -> Type[json.JSONEncoder]:
    """Get the JSON Encoder for the provided flask app

    Starting with flask version 2.2 the flask application provides a
    interface to register a custom JSON Encoder/Decoder under the json_provider_class.
    As this interface is not compatible with the standard JSONEncoder, the `default`
    method of the class is wrapped.

    Lookup Order:
      - app.json_encoder - For Flask < 2.2
      - app.json_provider_class.default
      - flask.json.provider.DefaultJSONProvider.default

    """
    if not HAS_JSON_PROVIDER:  # pragma: no cover
        return app.json_encoder  # type: ignore

    return JSONEncoder
