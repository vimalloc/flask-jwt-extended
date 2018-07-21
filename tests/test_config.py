import warnings

import pytest
from datetime import timedelta
from flask import Flask
from flask.json import JSONEncoder

from flask_jwt_extended import JWTManager
from flask_jwt_extended.config import config


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    JWTManager(app)
    return app


def test_default_configs(app):
    with app.test_request_context():
        assert config.token_location == ['headers']
        assert config.jwt_in_query_string is False
        assert config.jwt_in_cookies is False
        assert config.jwt_in_json is False
        assert config.jwt_in_headers is True

        assert config.header_name == 'Authorization'
        assert config.header_type == 'Bearer'

        assert config.query_string_name == 'jwt'

        assert config.access_cookie_name == 'access_token_cookie'
        assert config.refresh_cookie_name == 'refresh_token_cookie'
        assert config.access_cookie_path == '/'
        assert config.refresh_cookie_path == '/'
        assert config.cookie_secure is False
        assert config.cookie_domain is None
        assert config.session_cookie is True
        assert config.cookie_samesite is None

        assert config.json_key == 'access_token'
        assert config.refresh_json_key == 'refresh_token'

        assert config.csrf_protect is False
        assert config.csrf_request_methods == ['POST', 'PUT', 'PATCH', 'DELETE']
        assert config.csrf_in_cookies is True
        assert config.access_csrf_cookie_name == 'csrf_access_token'
        assert config.refresh_csrf_cookie_name == 'csrf_refresh_token'
        assert config.access_csrf_cookie_path == '/'
        assert config.refresh_csrf_cookie_path == '/'
        assert config.access_csrf_header_name == 'X-CSRF-TOKEN'
        assert config.refresh_csrf_header_name == 'X-CSRF-TOKEN'

        assert config.access_expires == timedelta(minutes=15)
        assert config.refresh_expires == timedelta(days=30)
        assert config.algorithm == 'HS256'
        assert config.is_asymmetric is False
        assert config.blacklist_enabled is False
        assert config.blacklist_checks == ['access', 'refresh']
        assert config.blacklist_access_tokens is True
        assert config.blacklist_refresh_tokens is True

        assert config.cookie_max_age is None

        assert config.identity_claim_key == 'identity'
        assert config.user_claims_key == 'user_claims'

        assert config.user_claims_in_refresh_token is False

        assert config.json_encoder is app.json_encoder

        assert config.error_msg_key == 'msg'


def test_override_configs(app):
    app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'query_string', 'json']
    app.config['JWT_HEADER_NAME'] = 'TestHeader'
    app.config['JWT_HEADER_TYPE'] = 'TestType'
    app.config['JWT_JSON_KEY'] = 'TestKey'
    app.config['JWT_REFRESH_JSON_KEY'] = 'TestRefreshKey'

    app.config['JWT_QUERY_STRING_NAME'] = 'banana'

    app.config['JWT_ACCESS_COOKIE_NAME'] = 'new_access_cookie'
    app.config['JWT_REFRESH_COOKIE_NAME'] = 'new_refresh_cookie'
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/access/path'
    app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh/path'
    app.config['JWT_COOKIE_SECURE'] = True
    app.config['JWT_COOKIE_DOMAIN'] = ".example.com"
    app.config['JWT_SESSION_COOKIE'] = False
    app.config['JWT_COOKIE_SAMESITE'] = "Strict"

    app.config['JWT_COOKIE_CSRF_PROTECT'] = True
    app.config['JWT_CSRF_METHODS'] = ['GET']
    app.config['JWT_CSRF_IN_COOKIES'] = False
    app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'access_csrf_cookie'
    app.config['JWT_REFRESH_CSRF_COOKIE_NAME'] = 'refresh_csrf_cookie'
    app.config['JWT_ACCESS_CSRF_COOKIE_PATH'] = '/csrf/access/path'
    app.config['JWT_REFRESH_CSRF_COOKIE_PATH'] = '/csrf/refresh/path'
    app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = 'X-ACCESS-CSRF'
    app.config['JWT_REFRESH_CSRF_HEADER_NAME'] = 'X-REFRESH-CSRF'

    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=5)
    app.config['JWT_ALGORITHM'] = 'HS512'

    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'

    app.config['JWT_IDENTITY_CLAIM'] = 'foo'
    app.config['JWT_USER_CLAIMS'] = 'bar'

    app.config['JWT_CLAIMS_IN_REFRESH_TOKEN'] = True

    app.config['JWT_ERROR_MESSAGE_KEY'] = 'message'

    class CustomJSONEncoder(JSONEncoder):
        pass

    app.json_encoder = CustomJSONEncoder

    with app.test_request_context():
        assert config.token_location == ['cookies', 'query_string', 'json']
        assert config.jwt_in_query_string is True
        assert config.jwt_in_cookies is True
        assert config.jwt_in_headers is False
        assert config.jwt_in_json is True
        assert config.header_name == 'TestHeader'
        assert config.header_type == 'TestType'
        assert config.json_key == 'TestKey'
        assert config.refresh_json_key == 'TestRefreshKey'

        assert config.query_string_name == 'banana'

        assert config.access_cookie_name == 'new_access_cookie'
        assert config.refresh_cookie_name == 'new_refresh_cookie'
        assert config.access_cookie_path == '/access/path'
        assert config.refresh_cookie_path == '/refresh/path'
        assert config.cookie_secure is True
        assert config.cookie_domain == ".example.com"
        assert config.session_cookie is False
        assert config.cookie_samesite == "Strict"

        assert config.csrf_protect is True
        assert config.csrf_request_methods == ['GET']
        assert config.csrf_in_cookies is False
        assert config.access_csrf_cookie_name == 'access_csrf_cookie'
        assert config.refresh_csrf_cookie_name == 'refresh_csrf_cookie'
        assert config.access_csrf_cookie_path == '/csrf/access/path'
        assert config.refresh_csrf_cookie_path == '/csrf/refresh/path'
        assert config.access_csrf_header_name == 'X-ACCESS-CSRF'
        assert config.refresh_csrf_header_name == 'X-REFRESH-CSRF'

        assert config.access_expires == timedelta(minutes=5)
        assert config.refresh_expires == timedelta(days=5)
        assert config.algorithm == 'HS512'

        assert config.blacklist_enabled is True
        assert config.blacklist_checks == ['refresh']
        assert config.blacklist_access_tokens is False
        assert config.blacklist_refresh_tokens is True

        assert config.cookie_max_age == 2147483647

        assert config.identity_claim_key == 'foo'
        assert config.user_claims_key == 'bar'

        assert config.user_claims_in_refresh_token is True

        assert config.json_encoder is CustomJSONEncoder

        assert config.error_msg_key == 'message'


def test_tokens_never_expire(app):
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = False
    with app.test_request_context():
        assert config.access_expires is False
        assert config.refresh_expires is False


# noinspection PyStatementEffect
def test_symmetric_secret_key(app):
    with app.test_request_context():
        assert config.is_asymmetric is False

        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        app.secret_key = 'foobar'
        with app.test_request_context():
            assert config.encode_key == 'foobar'
            assert config.decode_key == 'foobar'

        app.config['JWT_SECRET_KEY'] = 'foobarbaz'
        with app.test_request_context():
            assert config.encode_key == 'foobarbaz'
            assert config.decode_key == 'foobarbaz'


# noinspection PyStatementEffect
def test_default_with_asymmetric_secret_key(app):
    with app.test_request_context():
        app.config['JWT_ALGORITHM'] = 'RS256'
        assert config.is_asymmetric is True

        # If no key is entered, should raise an error
        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        # Make sure the secret key isn't being used for asymmetric stuff
        app.secret_key = 'foobar'
        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        # Make sure the secret key isn't being used for asymmetric stuff
        app.config['JWT_SECRET_KEY'] = 'foobarbaz'
        with pytest.raises(RuntimeError):
            config.encode_key
        with pytest.raises(RuntimeError):
            config.decode_key

        app.config['JWT_PUBLIC_KEY'] = 'foo2'
        app.config['JWT_PRIVATE_KEY'] = 'bar2'
        app.config['JWT_ALGORITHM'] = 'RS256'
        with app.test_request_context():
            assert config.decode_key == 'foo2'
            assert config.encode_key == 'bar2'


# noinspection PyStatementEffect
def test_invalid_config_options(app):
    with app.test_request_context():
        app.config['JWT_TOKEN_LOCATION'] = []
        with pytest.raises(RuntimeError):
            config.token_location

        app.config['JWT_TOKEN_LOCATION'] = 'banana'
        with pytest.raises(RuntimeError):
            config.token_location

        app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies', 'banana']
        with pytest.raises(RuntimeError):
            config.token_location

        app.config['JWT_HEADER_NAME'] = ''
        with app.test_request_context():
            with pytest.raises(RuntimeError):
                config.header_name

        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 'banana'
        with pytest.raises(RuntimeError):
            config.access_expires

        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 'banana'
        with pytest.raises(RuntimeError):
            config.refresh_expires

        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = True
        with pytest.raises(RuntimeError):
            config.access_expires

        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = True
        with pytest.raises(RuntimeError):
            config.refresh_expires

        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'banana'
        with pytest.raises(RuntimeError):
            config.blacklist_checks

        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'banana']
        with pytest.raises(RuntimeError):
            config.blacklist_checks


def test_jwt_token_locations_config(app):
    with app.test_request_context():
        app.config['JWT_TOKEN_LOCATION'] = 'headers'
        assert config.token_location == ['headers']
        app.config['JWT_TOKEN_LOCATION'] = ['headers']
        assert config.token_location == ['headers']
        app.config['JWT_TOKEN_LOCATION'] = 'cookies'
        assert config.token_location == ['cookies']
        app.config['JWT_TOKEN_LOCATION'] = ['cookies']
        assert config.token_location == ['cookies']
        app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
        assert config.token_location == ['cookies', 'headers']


def test_jwt_blacklist_token_checks_config(app):
    with app.test_request_context():
        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'access'
        assert config.blacklist_checks == ['access']
        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
        assert config.blacklist_checks == ['access']
        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'
        assert config.blacklist_checks == ['refresh']
        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['refresh']
        assert config.blacklist_checks == ['refresh']
        app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
        assert config.blacklist_checks == ['access', 'refresh']


def test_csrf_protect_config(app):
    with app.test_request_context():
        app.config['JWT_TOKEN_LOCATION'] = ['headers']
        app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        assert config.csrf_protect is False

        app.config['JWT_TOKEN_LOCATION'] = ['cookies']
        app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        assert config.csrf_protect is True

        app.config['JWT_TOKEN_LOCATION'] = ['cookies']
        app.config['JWT_COOKIE_CSRF_PROTECT'] = False
        assert config.csrf_protect is False


def test_depreciated_options(app):
    app.config['JWT_CSRF_HEADER_NAME'] = 'Auth'

    # Cause all warnings to always be triggered.
    warnings.simplefilter("always")

    # Verify our warnings are thrown
    with app.test_request_context():
        with warnings.catch_warnings(record=True) as w:
            assert config.access_csrf_header_name == 'Auth'
            assert config.refresh_csrf_header_name == 'Auth'
            assert len(w) == 2
            assert w[0].category == DeprecationWarning
            assert w[1].category == DeprecationWarning
