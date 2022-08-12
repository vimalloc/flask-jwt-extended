from datetime import datetime
from datetime import timedelta
from datetime import timezone
from json import JSONEncoder
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Type
from typing import Union

from flask import current_app
from jwt.algorithms import requires_cryptography

from flask_jwt_extended.internal_utils import get_json_encoder
from flask_jwt_extended.typing import ExpiresDelta


class _Config(object):
    """
    Helper object for accessing and verifying options in this extension. This
    is meant for internal use of the application; modifying config options
    should be done with flasks ```app.config```.

    Default values for the configuration options are set in the jwt_manager
    object. All of these values are read only. This is simply a loose wrapper
    with some helper functionality for flasks `app.config`.
    """

    @property
    def is_asymmetric(self) -> bool:
        return self.algorithm in requires_cryptography

    @property
    def encode_key(self) -> str:
        return self._private_key if self.is_asymmetric else self._secret_key

    @property
    def decode_key(self) -> str:
        return self._public_key if self.is_asymmetric else self._secret_key

    @property
    def token_location(self) -> Sequence[str]:
        locations = current_app.config["JWT_TOKEN_LOCATION"]
        if isinstance(locations, str):
            locations = (locations,)
        elif not isinstance(locations, Iterable):
            raise RuntimeError("JWT_TOKEN_LOCATION must be a sequence or a set")
        elif not locations:
            raise RuntimeError(
                "JWT_TOKEN_LOCATION must contain at least one "
                'of "headers", "cookies", "query_string", or "json"'
            )
        for location in locations:
            if location not in ("headers", "cookies", "query_string", "json"):
                raise RuntimeError(
                    "JWT_TOKEN_LOCATION can only contain "
                    '"headers", "cookies", "query_string", or "json"'
                )
        return locations

    @property
    def jwt_in_cookies(self) -> bool:
        return "cookies" in self.token_location

    @property
    def jwt_in_headers(self) -> bool:
        return "headers" in self.token_location

    @property
    def jwt_in_query_string(self) -> bool:
        return "query_string" in self.token_location

    @property
    def jwt_in_json(self) -> bool:
        return "json" in self.token_location

    @property
    def header_name(self) -> str:
        name = current_app.config["JWT_HEADER_NAME"]
        if not name:
            raise RuntimeError("JWT_ACCESS_HEADER_NAME cannot be empty")
        return name

    @property
    def header_type(self) -> str:
        return current_app.config["JWT_HEADER_TYPE"]

    @property
    def query_string_name(self) -> str:
        return current_app.config["JWT_QUERY_STRING_NAME"]

    @property
    def query_string_value_prefix(self) -> str:
        return current_app.config["JWT_QUERY_STRING_VALUE_PREFIX"]

    @property
    def access_cookie_name(self) -> str:
        return current_app.config["JWT_ACCESS_COOKIE_NAME"]

    @property
    def refresh_cookie_name(self) -> str:
        return current_app.config["JWT_REFRESH_COOKIE_NAME"]

    @property
    def access_cookie_path(self) -> str:
        return current_app.config["JWT_ACCESS_COOKIE_PATH"]

    @property
    def refresh_cookie_path(self) -> str:
        return current_app.config["JWT_REFRESH_COOKIE_PATH"]

    @property
    def cookie_secure(self) -> bool:
        return current_app.config["JWT_COOKIE_SECURE"]

    @property
    def cookie_domain(self) -> str:
        return current_app.config["JWT_COOKIE_DOMAIN"]

    @property
    def session_cookie(self) -> bool:
        return current_app.config["JWT_SESSION_COOKIE"]

    @property
    def cookie_samesite(self) -> str:
        return current_app.config["JWT_COOKIE_SAMESITE"]

    @property
    def json_key(self) -> str:
        return current_app.config["JWT_JSON_KEY"]

    @property
    def refresh_json_key(self) -> str:
        return current_app.config["JWT_REFRESH_JSON_KEY"]

    @property
    def csrf_protect(self) -> bool:
        return self.jwt_in_cookies and current_app.config["JWT_COOKIE_CSRF_PROTECT"]

    @property
    def csrf_request_methods(self) -> Iterable[str]:
        return current_app.config["JWT_CSRF_METHODS"]

    @property
    def csrf_in_cookies(self) -> bool:
        return current_app.config["JWT_CSRF_IN_COOKIES"]

    @property
    def access_csrf_cookie_name(self) -> str:
        return current_app.config["JWT_ACCESS_CSRF_COOKIE_NAME"]

    @property
    def refresh_csrf_cookie_name(self) -> str:
        return current_app.config["JWT_REFRESH_CSRF_COOKIE_NAME"]

    @property
    def access_csrf_cookie_path(self) -> str:
        return current_app.config["JWT_ACCESS_CSRF_COOKIE_PATH"]

    @property
    def refresh_csrf_cookie_path(self) -> str:
        return current_app.config["JWT_REFRESH_CSRF_COOKIE_PATH"]

    @property
    def access_csrf_header_name(self) -> str:
        return current_app.config["JWT_ACCESS_CSRF_HEADER_NAME"]

    @property
    def refresh_csrf_header_name(self) -> str:
        return current_app.config["JWT_REFRESH_CSRF_HEADER_NAME"]

    @property
    def csrf_check_form(self) -> bool:
        return current_app.config["JWT_CSRF_CHECK_FORM"]

    @property
    def access_csrf_field_name(self) -> str:
        return current_app.config["JWT_ACCESS_CSRF_FIELD_NAME"]

    @property
    def refresh_csrf_field_name(self) -> str:
        return current_app.config["JWT_REFRESH_CSRF_FIELD_NAME"]

    @property
    def access_expires(self) -> ExpiresDelta:
        delta = current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
        if type(delta) is int:
            delta = timedelta(seconds=delta)
        if delta is not False:
            try:
                # Basically runtime typechecking. Probably a better way to do
                # this with proper type checking
                delta + datetime.now(timezone.utc)
            except TypeError as e:
                err = (
                    "must be able to add JWT_ACCESS_TOKEN_EXPIRES to datetime.datetime"
                )
                raise RuntimeError(err) from e
        return delta

    @property
    def refresh_expires(self) -> ExpiresDelta:
        delta = current_app.config["JWT_REFRESH_TOKEN_EXPIRES"]
        if type(delta) is int:
            delta = timedelta(seconds=delta)
        if delta is not False:
            # Basically runtime typechecking. Probably a better way to do
            # this with proper type checking
            try:
                delta + datetime.now(timezone.utc)
            except TypeError as e:
                err = (
                    "must be able to add JWT_REFRESH_TOKEN_EXPIRES to datetime.datetime"
                )
                raise RuntimeError(err) from e
        return delta

    @property
    def algorithm(self) -> str:
        return current_app.config["JWT_ALGORITHM"]

    @property
    def decode_algorithms(self) -> List[str]:
        algorithms = current_app.config["JWT_DECODE_ALGORITHMS"]
        if not algorithms:
            return [self.algorithm]
        if self.algorithm not in algorithms:
            algorithms.append(self.algorithm)
        return algorithms

    @property
    def _secret_key(self) -> str:
        key = current_app.config["JWT_SECRET_KEY"]
        if not key:
            key = current_app.config.get("SECRET_KEY", None)
            if not key:
                raise RuntimeError(
                    "JWT_SECRET_KEY or flask SECRET_KEY "
                    "must be set when using symmetric "
                    'algorithm "{}"'.format(self.algorithm)
                )
        return key

    @property
    def _public_key(self) -> str:
        key = current_app.config["JWT_PUBLIC_KEY"]
        if not key:
            raise RuntimeError(
                "JWT_PUBLIC_KEY must be set to use "
                "asymmetric cryptography algorithm "
                '"{}"'.format(self.algorithm)
            )
        return key

    @property
    def _private_key(self) -> str:
        key = current_app.config["JWT_PRIVATE_KEY"]
        if not key:
            raise RuntimeError(
                "JWT_PRIVATE_KEY must be set to use "
                "asymmetric cryptography algorithm "
                '"{}"'.format(self.algorithm)
            )
        return key

    @property
    def cookie_max_age(self) -> Optional[int]:
        # Returns the appropiate value for max_age for flask set_cookies. If
        # session cookie is true, return None, otherwise return a number of
        # seconds 1 year in the future
        return None if self.session_cookie else 31540000  # 1 year

    @property
    def identity_claim_key(self) -> str:
        return current_app.config["JWT_IDENTITY_CLAIM"]

    @property
    def exempt_methods(self) -> Iterable[str]:
        return {"OPTIONS"}

    @property
    def error_msg_key(self) -> str:
        return current_app.config["JWT_ERROR_MESSAGE_KEY"]

    @property
    def json_encoder(self) -> Type[JSONEncoder]:
        return get_json_encoder(current_app)

    @property
    def decode_audience(self) -> Union[str, Iterable[str]]:
        return current_app.config["JWT_DECODE_AUDIENCE"]

    @property
    def encode_audience(self) -> Union[str, Iterable[str]]:
        return current_app.config["JWT_ENCODE_AUDIENCE"]

    @property
    def encode_issuer(self) -> str:
        return current_app.config["JWT_ENCODE_ISSUER"]

    @property
    def decode_issuer(self) -> str:
        return current_app.config["JWT_DECODE_ISSUER"]

    @property
    def leeway(self) -> int:
        return current_app.config["JWT_DECODE_LEEWAY"]

    @property
    def encode_nbf(self) -> bool:
        return current_app.config["JWT_ENCODE_NBF"]


config = _Config()
