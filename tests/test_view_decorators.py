from datetime import timedelta

import pytest
from dateutil.relativedelta import relativedelta
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import decode_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import verify_jwt_in_request
from tests.utils import encode_token
from tests.utils import get_jwt_manager
from tests.utils import make_headers


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    JWTManager(app)

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def protected():
        return jsonify(foo="bar")

    @app.route("/fresh_protected", methods=["GET"])
    @jwt_required(fresh=True)
    def fresh_protected():
        return jsonify(foo="bar")

    @app.route("/refresh_protected", methods=["GET"])
    @jwt_required(refresh=True)
    def refresh_protected():
        return jsonify(foo="bar")

    @app.route("/optional_protected", methods=["GET"])
    @jwt_required(optional=True)
    def optional_protected():
        if get_jwt_identity():
            return jsonify(foo="baz")
        else:
            return jsonify(foo="bar")

    return app


def test_jwt_required(app):
    url = "/protected"

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")
        fresh_access_token = create_access_token("username", fresh=True)
        refresh_token = create_refresh_token("username")

    # Access and fresh access should be able to access this
    for token in (access_token, fresh_access_token):
        response = test_client.get(url, headers=make_headers(token))
        assert response.status_code == 200
        assert response.get_json() == {"foo": "bar"}

    # Test accessing jwt_required with no jwt in the request
    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing Authorization Header"}

    # Test refresh token access to jwt_required
    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Only non-refresh tokens are allowed"}


def test_fresh_jwt_required(app):
    jwtM = get_jwt_manager(app)
    url = "/fresh_protected"

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")
        fresh_access_token = create_access_token("username", fresh=True)
        refresh_token = create_refresh_token("username")
        fresh_timed_access_token = create_access_token(
            identity="username", fresh=timedelta(minutes=5)
        )
        stale_timed_access_token = create_access_token(
            identity="username", fresh=timedelta(minutes=-1)
        )

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Fresh token required"}

    response = test_client.get(url, headers=make_headers(fresh_timed_access_token))
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    response = test_client.get(url, headers=make_headers(stale_timed_access_token))
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Fresh token required"}

    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing Authorization Header"}

    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Only non-refresh tokens are allowed"}

    # Test with custom response
    @jwtM.needs_fresh_token_loader
    def custom_response(jwt_header, jwt_data):
        assert jwt_header["alg"] == "HS256"
        assert jwt_data["sub"] == "username"
        return jsonify(msg="foobar"), 201

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 201
    assert response.get_json() == {"msg": "foobar"}


def test_refresh_jwt_required(app):
    url = "/refresh_protected"

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")
        fresh_access_token = create_access_token("username", fresh=True)
        refresh_token = create_refresh_token("username")

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Only refresh tokens are allowed"}

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Only refresh tokens are allowed"}

    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing Authorization Header"}

    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}


@pytest.mark.parametrize("delta_func", [timedelta, relativedelta])
def test_jwt_optional(app, delta_func):
    url = "/optional_protected"

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")
        fresh_access_token = create_access_token("username", fresh=True)
        refresh_token = create_refresh_token("username")
        expired_token = create_access_token(
            identity="username", expires_delta=delta_func(minutes=-1)
        )

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    assert response.status_code == 200
    assert response.get_json() == {"foo": "baz"}

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 200
    assert response.get_json() == {"foo": "baz"}

    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Only non-refresh tokens are allowed"}

    response = test_client.get(url, headers=make_headers(expired_token))
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Token has expired"}


def test_jwt_optional_with_no_valid_jwt(app):
    url = "/optional_protected"
    test_client = app.test_client()

    # No auth headers
    response = test_client.get(url, headers=None)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # auth header with type that isn't configured to be checked
    response = test_client.get(url, headers={"Authorization": "basic creds"})
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # auth header with Bearer type but no JWT
    response = test_client.get(url, headers={"Authorization": "Bearer "})
    assert response.status_code == 422
    assert response.get_json() == {
        "msg": "Bad Authorization header. Expected 'Authorization: Bearer <JWT>'"
    }

    # Bearer token malformed
    response = test_client.get(url, headers={"Authorization": "Bearer xxx"})
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Not enough segments"}

    # auth header comma seperated with no bearer token
    response = test_client.get(url, headers={"Authorization": "Foo 1, Bar 2, Baz, 3"})
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # auth header comma seperated with missing bearer token
    response = test_client.get(url, headers={"Authorization": "Foo 1, Bearer, Baz, 3"})
    assert response.status_code == 422
    assert response.get_json() == {
        "msg": "Bad Authorization header. Expected 'Authorization: Bearer <JWT>'"
    }

    # Bearer token comma seperated with malformed bearer token
    response = test_client.get(
        url, headers={"Authorization": "Foo 1, Bearer 2, Baz, 3"}
    )
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Not enough segments"}


def test_override_jwt_location(app):
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]

    @app.route("/protected_other")
    @jwt_required(locations="headers")
    def protected_other():
        return jsonify(foo="bar")

    @app.route("/protected_invalid")
    @jwt_required(locations="INVALID_LOCATION")
    def protected_invalid():
        return jsonify(foo="bar")

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")

    url = "/protected_other"
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {"foo": "bar"}
    assert response.status_code == 200

    url = "/protected"
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 401
    assert response.get_json() == {"msg": 'Missing cookie "access_token_cookie"'}

    url = "/protected_invalid"
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 500


def test_invalid_jwt(app):
    url = "/protected"
    jwtM = get_jwt_manager(app)
    test_client = app.test_client()
    invalid_token = "aaaaa.bbbbb.ccccc"

    # Test default response
    response = test_client.get(url, headers=make_headers(invalid_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Invalid header padding"}

    # Test custom response
    @jwtM.invalid_token_loader
    def custom_response(err_str):
        return jsonify(msg="foobar"), 201

    response = test_client.get(url, headers=make_headers(invalid_token))
    assert response.status_code == 201
    assert response.get_json() == {"msg": "foobar"}


def test_jwt_missing_claims(app):
    url = "/protected"
    test_client = app.test_client()
    token = encode_token(app, {"foo": "bar"})

    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Missing claim: sub"}


def test_jwt_invalid_audience(app):
    url = "/protected"
    test_client = app.test_client()

    # No audience claim expected or provided - OK
    access_token = encode_token(app, {"sub": "me"})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 200

    # Audience claim expected and not provided - not OK
    app.config["JWT_DECODE_AUDIENCE"] = "my_audience"
    access_token = encode_token(app, {"sub": "me"})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": 'Token is missing the "aud" claim'}

    # Audience claim still expected and wrong one provided - not OK
    access_token = encode_token(app, {"aud": "different_audience", "sub": "me"})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Invalid audience"}


def test_jwt_invalid_issuer(app):
    url = "/protected"
    test_client = app.test_client()

    # No issuer claim expected or provided - OK
    access_token = encode_token(app, {"sub": "me"})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 200

    # Issuer claim expected and not provided - not OK
    app.config["JWT_DECODE_ISSUER"] = "my_issuer"
    access_token = encode_token(app, {"sub": "me"})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": 'Token is missing the "iss" claim'}

    # Issuer claim still expected and wrong one provided - not OK
    access_token = encode_token(app, {"iss": "different_issuer", "sub": "me"})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Invalid issuer"}


def test_malformed_token(app):
    url = "/protected"
    test_client = app.test_client()

    access_token = "foobarbaz"
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "Not enough segments"}


@pytest.mark.parametrize("delta_func", [timedelta, relativedelta])
def test_expired_token(app, delta_func):
    url = "/protected"
    jwtM = get_jwt_manager(app)
    test_client = app.test_client()
    with app.test_request_context():
        token = create_access_token("username", expires_delta=delta_func(minutes=-1))

    # Test default response
    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Token has expired"}

    # Test new custom response
    @jwtM.expired_token_loader
    def custom_response(expired_jwt_header, expired_jwt_data):
        assert expired_jwt_header["alg"] == "HS256"
        assert expired_jwt_data["sub"] == "username"
        assert expired_jwt_data["type"] == "access"
        return jsonify(msg="foobar"), 201

    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 201
    assert response.get_json() == {"msg": "foobar"}


def test_expired_token_via_decode_token(app):
    jwtM = get_jwt_manager(app)

    @jwtM.expired_token_loader
    def depreciated_custom_response(expired_jwt_header, expired_jwt_data):
        assert expired_jwt_header["alg"] == "HS256"
        assert expired_jwt_data["sub"] == "username"
        return jsonify(msg="foobar"), 401

    @app.route("/test")
    def test_route():
        token = create_access_token("username", expires_delta=timedelta(minutes=-1))
        decode_token(token)
        return jsonify(msg="baz"), 200

    test_client = app.test_client()
    response = test_client.get("/test")
    assert response.get_json() == {"msg": "foobar"}
    assert response.status_code == 401


def test_no_token(app):
    url = "/protected"
    jwtM = get_jwt_manager(app)
    test_client = app.test_client()

    # Test default response
    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing Authorization Header"}

    # Test custom response
    @jwtM.unauthorized_loader
    def custom_response(err_str):
        return jsonify(msg="foobar"), 201

    response = test_client.get(url, headers=None)
    assert response.status_code == 201
    assert response.get_json() == {"msg": "foobar"}


def test_different_token_algorightm(app):
    url = "/protected"
    test_client = app.test_client()
    with app.test_request_context():
        token = create_access_token("username")

    app.config["JWT_ALGORITHM"] = "HS512"

    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 422
    assert response.get_json() == {"msg": "The specified alg value is not allowed"}


def test_verify_jwt_in_request_returns_decoded_token(app):
    @app.route("/custom", methods=["GET"])
    def custom():
        jwt_header, jwt_data = verify_jwt_in_request()
        assert jwt_header["alg"] == "HS256"
        assert jwt_data["sub"] == "username"
        return jsonify(foo="bar")

    url = "/custom"
    test_client = app.test_client()
    with app.test_request_context():
        token = create_access_token("username")

    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}
