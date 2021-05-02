from datetime import timedelta

import pytest
from dateutil.relativedelta import relativedelta
from flask import Flask
from flask.json import JSONEncoder

from flask_jwt_extended import JWTManager
from flask_jwt_extended.config import config


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    JWTManager(app)
    return app


def test_default_configs(app):
    with app.test_request_context():
        assert config.token_location == ("headers",)
        assert config.jwt_in_query_string is False
        assert config.jwt_in_cookies is False
        assert config.jwt_in_json is False
        assert config.jwt_in_headers is True

        assert config.encode_issuer is None
        assert config.decode_issuer is None

        assert config.header_name == "Authorization"
        assert config.header_type == "Bearer"

        assert config.query_string_name == "jwt"
        assert config.query_string_value_prefix == ""

        assert config.access_cookie_name == "access_token_cookie"
        assert config.refresh_cookie_name == "refresh_token_cookie"
        assert config.access_cookie_path == "/"
        assert config.refresh_cookie_path == "/"
        assert config.cookie_secure is False
        assert config.cookie_domain is None
        assert config.session_cookie is True
        assert config.cookie_samesite is None

        assert config.json_key == "access_token"
        assert config.refresh_json_key == "refresh_token"

        assert config.csrf_protect is False
        assert config.csrf_request_methods == ["POST", "PUT", "PATCH", "DELETE"]
        assert config.csrf_in_cookies is True
        assert config.access_csrf_cookie_name == "csrf_access_token"
        assert config.refresh_csrf_cookie_name == "csrf_refresh_token"
        assert config.access_csrf_cookie_path == "/"
        assert config.refresh_csrf_cookie_path == "/"
        assert config.access_csrf_header_name == "X-CSRF-TOKEN"
        assert config.refresh_csrf_header_name == "X-CSRF-TOKEN"

        assert config.access_expires == timedelta(minutes=15)
        assert config.refresh_expires == timedelta(days=30)
        assert config.algorithm == "HS256"
        assert config.decode_algorithms == ["HS256"]
        assert config.is_asymmetric is False

        assert config.cookie_max_age is None

        assert config.identity_claim_key == "sub"

        assert config.json_encoder is app.json_encoder

        assert config.error_msg_key == "msg"


@pytest.mark.parametrize("delta_func", [timedelta, relativedelta])
def test_override_configs(app, delta_func):
    app.config["JWT_TOKEN_LOCATION"] = ["cookies", "query_string", "json"]
    app.config["JWT_HEADER_NAME"] = "TestHeader"
    app.config["JWT_HEADER_TYPE"] = "TestType"
    app.config["JWT_JSON_KEY"] = "TestKey"
    app.config["JWT_REFRESH_JSON_KEY"] = "TestRefreshKey"

    app.config["JWT_DECODE_ISSUER"] = "TestDecodeIssuer"
    app.config["JWT_ENCODE_ISSUER"] = "TestEncodeIssuer"

    app.config["JWT_QUERY_STRING_NAME"] = "banana"
    app.config["JWT_QUERY_STRING_VALUE_PREFIX"] = "kiwi"

    app.config["JWT_ACCESS_COOKIE_NAME"] = "new_access_cookie"
    app.config["JWT_REFRESH_COOKIE_NAME"] = "new_refresh_cookie"
    app.config["JWT_ACCESS_COOKIE_PATH"] = "/access/path"
    app.config["JWT_REFRESH_COOKIE_PATH"] = "/refresh/path"
    app.config["JWT_COOKIE_SECURE"] = True
    app.config["JWT_COOKIE_DOMAIN"] = ".example.com"
    app.config["JWT_SESSION_COOKIE"] = False
    app.config["JWT_COOKIE_SAMESITE"] = "Strict"

    app.config["JWT_COOKIE_CSRF_PROTECT"] = True
    app.config["JWT_CSRF_METHODS"] = ["GET"]
    app.config["JWT_CSRF_IN_COOKIES"] = False
    app.config["JWT_ACCESS_CSRF_COOKIE_NAME"] = "access_csrf_cookie"
    app.config["JWT_REFRESH_CSRF_COOKIE_NAME"] = "refresh_csrf_cookie"
    app.config["JWT_ACCESS_CSRF_COOKIE_PATH"] = "/csrf/access/path"
    app.config["JWT_REFRESH_CSRF_COOKIE_PATH"] = "/csrf/refresh/path"
    app.config["JWT_ACCESS_CSRF_HEADER_NAME"] = "X-ACCESS-CSRF"
    app.config["JWT_REFRESH_CSRF_HEADER_NAME"] = "X-REFRESH-CSRF"

    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = delta_func(minutes=5)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = delta_func(days=5)
    app.config["JWT_ALGORITHM"] = "HS512"
    app.config["JWT_DECODE_ALGORITHMS"] = ["HS512", "HS256"]

    app.config["JWT_IDENTITY_CLAIM"] = "foo"

    app.config["JWT_ERROR_MESSAGE_KEY"] = "message"

    class CustomJSONEncoder(JSONEncoder):
        pass

    app.json_encoder = CustomJSONEncoder

    with app.test_request_context():
        assert config.token_location == ["cookies", "query_string", "json"]
        assert config.jwt_in_query_string is True
        assert config.jwt_in_cookies is True
        assert config.jwt_in_headers is False
        assert config.jwt_in_json is True
        assert config.header_name == "TestHeader"
        assert config.header_type == "TestType"
        assert config.json_key == "TestKey"
        assert config.refresh_json_key == "TestRefreshKey"

        assert config.decode_issuer == "TestDecodeIssuer"
        assert config.encode_issuer == "TestEncodeIssuer"

        assert config.query_string_name == "banana"
        assert config.query_string_value_prefix == "kiwi"

        assert config.access_cookie_name == "new_access_cookie"
        assert config.refresh_cookie_name == "new_refresh_cookie"
        assert config.access_cookie_path == "/access/path"
        assert config.refresh_cookie_path == "/refresh/path"
        assert config.cookie_secure is True
        assert config.cookie_domain == ".example.com"
        assert config.session_cookie is False
        assert config.cookie_samesite == "Strict"

        assert config.csrf_protect is True
        assert config.csrf_request_methods == ["GET"]
        assert config.csrf_in_cookies is False
        assert config.access_csrf_cookie_name == "access_csrf_cookie"
        assert config.refresh_csrf_cookie_name == "refresh_csrf_cookie"
        assert config.access_csrf_cookie_path == "/csrf/access/path"
        assert config.refresh_csrf_cookie_path == "/csrf/refresh/path"
        assert config.access_csrf_header_name == "X-ACCESS-CSRF"
        assert config.refresh_csrf_header_name == "X-REFRESH-CSRF"

        assert config.access_expires == delta_func(minutes=5)
        assert config.refresh_expires == delta_func(days=5)
        assert config.algorithm == "HS512"
        assert config.decode_algorithms == ["HS512", "HS256"]

        assert config.cookie_max_age == 31540000

        assert config.identity_claim_key == "foo"

        assert config.json_encoder is CustomJSONEncoder

        assert config.error_msg_key == "message"


def test_tokens_never_expire(app):
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = False
    with app.test_request_context():
        assert config.access_expires is False
        assert config.refresh_expires is False


def test_tokens_with_int_values(app):
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 300
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 432000

    with app.test_request_context():
        assert config.access_expires == timedelta(minutes=5)
        assert config.refresh_expires == timedelta(days=5)


# noinspection PyStatementEffect
def test_symmetric_secret_key(app):
    with app.test_request_context():
        assert config.is_asymmetric is False

        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        app.secret_key = "foobar"
        with app.test_request_context():
            assert config.encode_key == "foobar"
            assert config.decode_key == "foobar"

        app.config["JWT_SECRET_KEY"] = "foobarbaz"
        with app.test_request_context():
            assert config.encode_key == "foobarbaz"
            assert config.decode_key == "foobarbaz"


# noinspection PyStatementEffect
def test_default_with_asymmetric_secret_key(app):
    with app.test_request_context():
        app.config["JWT_ALGORITHM"] = "RS256"
        assert config.is_asymmetric is True

        # If no key is entered, should raise an error
        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        # Make sure the secret key isn't being used for asymmetric stuff
        app.secret_key = "foobar"
        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        # Make sure the secret key isn't being used for asymmetric stuff
        app.config["JWT_SECRET_KEY"] = "foobarbaz"
        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        app.config["JWT_PUBLIC_KEY"] = "foo2"
        app.config["JWT_PRIVATE_KEY"] = "bar2"
        app.config["JWT_ALGORITHM"] = "RS256"
        with app.test_request_context():
            assert config.decode_key == "foo2"
            assert config.encode_key == "bar2"


# noinspection PyStatementEffect
def test_invalid_config_options(app):
    with app.test_request_context():
        app.config["JWT_TOKEN_LOCATION"] = []
        with pytest.raises(RuntimeError):
            config.token_location

        app.config["JWT_TOKEN_LOCATION"] = "banana"
        with pytest.raises(RuntimeError):
            config.token_location

        app.config["JWT_TOKEN_LOCATION"] = 1
        with pytest.raises(RuntimeError):
            config.token_location

        app.config["JWT_TOKEN_LOCATION"] = {"location": "headers"}
        with pytest.raises(RuntimeError):
            config.token_location

        app.config["JWT_TOKEN_LOCATION"] = range(99)
        with pytest.raises(RuntimeError):
            config.token_location

        app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "banana"]
        with pytest.raises(RuntimeError):
            config.token_location

        app.config["JWT_HEADER_NAME"] = ""
        with app.test_request_context():
            with pytest.raises(RuntimeError):
                config.header_name

        app.config["JWT_ACCESS_TOKEN_EXPIRES"] = "banana"
        with pytest.raises(RuntimeError):
            config.access_expires

        app.config["JWT_REFRESH_TOKEN_EXPIRES"] = "banana"
        with pytest.raises(RuntimeError):
            config.refresh_expires

        app.config["JWT_ACCESS_TOKEN_EXPIRES"] = True
        with pytest.raises(RuntimeError):
            config.access_expires

        app.config["JWT_REFRESH_TOKEN_EXPIRES"] = True
        with pytest.raises(RuntimeError):
            config.refresh_expires


def test_jwt_token_locations_config(app):
    with app.test_request_context():
        allowed_locations = ("headers", "cookies", "query_string", "json")
        allowed_data_structures = (tuple, list, frozenset, set)

        for location in allowed_locations:
            app.config["JWT_TOKEN_LOCATION"] = location
            assert config.token_location == (location,)

        for locations in (
            data_structure((location,))
            for data_structure in allowed_data_structures
            for location in allowed_locations
        ):
            app.config["JWT_TOKEN_LOCATION"] = locations
            assert config.token_location == locations

        for locations in (
            data_structure(allowed_locations[:i])
            for data_structure in allowed_data_structures
            for i in range(1, len(allowed_locations))
        ):
            app.config["JWT_TOKEN_LOCATION"] = locations
            assert config.token_location == locations


def test_csrf_protect_config(app):
    with app.test_request_context():
        app.config["JWT_TOKEN_LOCATION"] = ["headers"]
        app.config["JWT_COOKIE_CSRF_PROTECT"] = True
        assert config.csrf_protect is False

        app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
        app.config["JWT_COOKIE_CSRF_PROTECT"] = True
        assert config.csrf_protect is True

        app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
        app.config["JWT_COOKIE_CSRF_PROTECT"] = False
        assert config.csrf_protect is False


def test_missing_algorithm_in_decode_algorithms(app):
    app.config["JWT_ALGORITHM"] = "RS256"
    app.config["JWT_DECODE_ALGORITHMS"] = ["HS512"]

    with app.test_request_context():
        assert config.decode_algorithms == ["HS512", "RS256"]
