from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from dateutil.relativedelta import relativedelta
from flask import Flask
from jwt import DecodeError
from jwt import ExpiredSignatureError
from jwt import ImmatureSignatureError
from jwt import InvalidAudienceError
from jwt import InvalidIssuerError
from jwt import InvalidSignatureError
from jwt import MissingRequiredClaimError

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import decode_token
from flask_jwt_extended import get_jti
from flask_jwt_extended import get_unverified_jwt_headers
from flask_jwt_extended import JWTManager
from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import JWTDecodeError
from tests.utils import encode_token
from tests.utils import get_jwt_manager


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "change_me"
    app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
    app.config["JWT_COOKIE_CSRF_PROTECT"] = True
    JWTManager(app)
    return app


@pytest.fixture(scope="function")
def default_access_token(app):
    with app.test_request_context():
        return {
            "jti": "1234",
            config.identity_claim_key: "username",
            "type": "access",
            "fresh": True,
            "csrf": "abcd",
        }


@pytest.mark.parametrize("missing_claims", ["sub", "csrf"])
def test_missing_claims(app, default_access_token, missing_claims):
    del default_access_token[missing_claims]
    missing_jwt_token = encode_token(app, default_access_token)

    with pytest.raises(JWTDecodeError):
        with app.test_request_context():
            decode_token(missing_jwt_token, csrf_value="abcd")


def test_default_decode_token_values(app, default_access_token):
    del default_access_token["type"]
    del default_access_token["jti"]
    del default_access_token["fresh"]
    token = encode_token(app, default_access_token)

    with app.test_request_context():
        decoded = decode_token(token)
        assert decoded["type"] == "access"
        assert decoded["jti"] is None
        assert decoded["fresh"] is False


def test_supports_decoding_other_token_types(app, default_access_token):
    default_access_token["type"] = "app"
    other_token = encode_token(app, default_access_token)

    with app.test_request_context():
        decoded = decode_token(other_token)
        assert decoded["type"] == "app"


def test_encode_decode_audience(app):
    # Default, no audience
    with app.test_request_context():
        encoded_token = create_access_token("username")
        decoded_token = decode_token(encoded_token)
        with pytest.raises(KeyError):
            decoded_token["aud"]

    # Encode and decode audience configured
    app.config["JWT_ENCODE_AUDIENCE"] = "foo"
    app.config["JWT_DECODE_AUDIENCE"] = "foo"
    with app.test_request_context():
        encoded_token = create_access_token("username")
        decoded_token = decode_token(encoded_token)
        assert decoded_token["aud"] == "foo"

    # Encode and decode mismatch
    app.config["JWT_ENCODE_AUDIENCE"] = "foo"
    app.config["JWT_DECODE_AUDIENCE"] = "bar"
    with app.test_request_context():
        encoded_token = create_access_token("username")
        with pytest.raises(InvalidAudienceError):
            decode_token(encoded_token)

    # No encode defined
    app.config["JWT_ENCODE_AUDIENCE"] = None
    app.config["JWT_DECODE_AUDIENCE"] = "foo"
    with app.test_request_context():
        encoded_token = create_access_token("username")
        with pytest.raises(MissingRequiredClaimError):
            decode_token(encoded_token)

    # No decode defined
    app.config["JWT_ENCODE_AUDIENCE"] = "foo"
    app.config["JWT_DECODE_AUDIENCE"] = None
    with app.test_request_context():
        encoded_token = create_access_token("username")
        decoded_token = decode_token(encoded_token)
        assert decoded_token["aud"] == "foo"


@pytest.mark.parametrize("delta_func", [timedelta, relativedelta])
def test_expired_token(app, delta_func):
    with app.test_request_context():
        delta = delta_func(minutes=-5)
        access_token = create_access_token("username", expires_delta=delta)
        refresh_token = create_refresh_token("username", expires_delta=delta)
        with pytest.raises(ExpiredSignatureError):
            decode_token(access_token)
        with pytest.raises(ExpiredSignatureError):
            decode_token(refresh_token)


@pytest.mark.parametrize("delta_func", [timedelta, relativedelta])
def test_allow_expired_token(app, delta_func):
    with app.test_request_context():
        delta = delta_func(minutes=-5)
        access_token = create_access_token("username", expires_delta=delta)
        refresh_token = create_refresh_token("username", expires_delta=delta)
        for token in (access_token, refresh_token):
            decoded = decode_token(token, allow_expired=True)
            assert decoded["sub"] == "username"
            assert "exp" in decoded


def test_never_expire_token(app):
    with app.test_request_context():
        access_token = create_access_token("username", expires_delta=False)
        refresh_token = create_refresh_token("username", expires_delta=False)
        for token in (access_token, refresh_token):
            decoded = decode_token(token)
            assert "exp" not in decoded


def test_nbf_token_in_future(app):
    date_in_future = datetime.utcnow() + timedelta(seconds=30)

    with pytest.raises(ImmatureSignatureError):
        with app.test_request_context():
            access_token = create_access_token(
                "username", additional_claims={"nbf": date_in_future}
            )
            decode_token(access_token)

    with app.test_request_context():
        app.config["JWT_DECODE_LEEWAY"] = 30
        access_token = create_access_token("username")
        decode_token(access_token)


def test_alternate_identity_claim(app, default_access_token):
    app.config["JWT_IDENTITY_CLAIM"] = "banana"

    # Insure decoding fails if the claim isn't there
    token = encode_token(app, default_access_token)
    with pytest.raises(JWTDecodeError):
        with app.test_request_context():
            decode_token(token)

    # Insure the claim exists in the decoded jwt
    del default_access_token["sub"]
    default_access_token["banana"] = "username"
    token = encode_token(app, default_access_token)
    with app.test_request_context():
        decoded = decode_token(token)
        assert "banana" in decoded
        assert "sub" not in decoded


def test_get_jti(app, default_access_token):
    token = encode_token(app, default_access_token)

    with app.test_request_context():
        assert default_access_token["jti"] == get_jti(token)


def test_encode_decode_callback_values(app, default_access_token):
    jwtM = get_jwt_manager(app)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    with app.test_request_context():
        assert jwtM._decode_key_callback({}, {}) == "foobarbaz"
        assert jwtM._encode_key_callback({}) == "foobarbaz"

    @jwtM.encode_key_loader
    def get_encode_key_1(identity):
        return "different secret"

    assert jwtM._encode_key_callback("") == "different secret"

    @jwtM.decode_key_loader
    def get_decode_key_1(jwt_header, jwt_data):
        return "different secret"

    assert jwtM._decode_key_callback({}, {}) == "different secret"


def test_custom_encode_decode_key_callbacks(app, default_access_token):
    jwtM = get_jwt_manager(app)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"

    @jwtM.encode_key_loader
    def get_encode_key_1(identity):
        assert identity == "username"
        return "different secret"

    with pytest.raises(InvalidSignatureError):
        with app.test_request_context():
            token = create_access_token("username")
            decode_token(token)
    with pytest.raises(InvalidSignatureError):
        with app.test_request_context():
            token = create_refresh_token("username")
            decode_token(token)

    @jwtM.decode_key_loader
    def get_decode_key_1(jwt_header, jwt_data):
        assert jwt_header["alg"] == "HS256"
        assert jwt_data["sub"] == "username"
        return "different secret"

    with app.test_request_context():
        token = create_access_token("username")
        decode_token(token)
        token = create_refresh_token("username")
        decode_token(token)


@pytest.mark.parametrize("token_aud", ["foo", ["bar"], ["foo", "bar", "baz"]])
def test_valid_aud(app, default_access_token, token_aud):
    app.config["JWT_DECODE_AUDIENCE"] = ["foo", "bar"]

    default_access_token["aud"] = token_aud
    valid_token = encode_token(app, default_access_token)
    with app.test_request_context():
        decoded = decode_token(valid_token)
        assert decoded["aud"] == token_aud


@pytest.mark.parametrize("token_aud", ["bar", ["bar"], ["bar", "baz"]])
def test_invalid_aud(app, default_access_token, token_aud):
    app.config["JWT_DECODE_AUDIENCE"] = "foo"

    default_access_token["aud"] = token_aud
    invalid_token = encode_token(app, default_access_token)
    with pytest.raises(InvalidAudienceError):
        with app.test_request_context():
            decode_token(invalid_token)


@pytest.mark.parametrize("token_aud", ["bar", ["bar"], ["bar", "baz"]])
def test_verify_no_aud(app, default_access_token, token_aud):
    app.config["JWT_DECODE_AUDIENCE"] = None

    default_access_token["aud"] = token_aud
    valid_token = encode_token(app, default_access_token)
    with app.test_request_context():
        decoded = decode_token(valid_token)
        assert decoded["aud"] == token_aud


def test_encode_iss(app, default_access_token):
    app.config["JWT_ENCODE_ISSUER"] = "foobar"

    with app.test_request_context():
        access_token = create_access_token("username")
        decoded = decode_token(access_token)
        assert decoded["iss"] == "foobar"


def test_mismatch_iss(app, default_access_token):
    app.config["JWT_ENCODE_ISSUER"] = "foobar"
    app.config["JWT_DECODE_ISSUER"] = "baz"

    with pytest.raises(InvalidIssuerError):
        with app.test_request_context():
            invalid_token = create_access_token("username")
            decode_token(invalid_token)


def test_valid_decode_iss(app, default_access_token):
    app.config["JWT_DECODE_ISSUER"] = "foobar"

    default_access_token["iss"] = "foobar"
    valid_token = encode_token(app, default_access_token)
    with app.test_request_context():
        decoded = decode_token(valid_token)
        assert decoded["iss"] == "foobar"


def test_invalid_decode_iss(app, default_access_token):
    app.config["JWT_DECODE_ISSUER"] = "baz"

    default_access_token["iss"] = "foobar"
    invalid_token = encode_token(app, default_access_token)
    with pytest.raises(InvalidIssuerError):
        with app.test_request_context():
            decode_token(invalid_token)


def test_malformed_token(app):
    invalid_token = "foobarbaz"
    with pytest.raises(DecodeError):
        with app.test_request_context():
            decode_token(invalid_token)


def test_jwt_headers(app):
    jwt_header = {"foo": "bar"}
    with app.test_request_context():
        access_token = create_access_token("username", additional_headers=jwt_header)
        refresh_token = create_refresh_token("username", additional_headers=jwt_header)
        assert get_unverified_jwt_headers(access_token)["foo"] == "bar"
        assert get_unverified_jwt_headers(refresh_token)["foo"] == "bar"


def test_token_expires_time(app):
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(hours=2)

    now_timestamp = datetime.timestamp(datetime.now(timezone.utc))

    with app.test_request_context():
        access_token = create_access_token("username")
        refresh_token = create_refresh_token("username")
        access_timestamp = decode_token(access_token)["exp"]
        refresh_timestamp = decode_token(refresh_token)["exp"]

        # <  2 for a little bit of leeway from when we calculated now vs when
        # the tokens are created
        assert (access_timestamp - (now_timestamp + 3600)) < 2
        assert (refresh_timestamp - (now_timestamp + 7200)) < 2


def test_nbf_is_present_by_default(app):
    with app.test_request_context():
        access_token = create_access_token("username", fresh=True)
        decoded = decode_token(access_token)
        assert "nbf" in decoded


def test_disable_nbf_encoding(app):
    app.config["JWT_ENCODE_NBF"] = False
    with app.test_request_context():
        access_token = create_access_token("username", fresh=True)
        decoded = decode_token(access_token)
        assert "nbf" not in decoded
