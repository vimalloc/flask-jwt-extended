import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from tests.utils import get_jwt_manager


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    JWTManager(app)

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def access_protected():
        return jsonify(foo="bar")

    return app


def test_default_headers(app):
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    # Ensure other authorization types don't work
    access_headers = {"Authorization": "Basic basiccreds"}
    response = test_client.get("/protected", headers=access_headers)
    error_msg = (
        "Missing 'Bearer' type in 'Authorization' header. "
        "Expected 'Authorization: Bearer <JWT>'"
    )
    assert response.status_code == 401
    assert response.get_json() == {"msg": error_msg}

    # Ensure default headers work
    access_headers = {"Authorization": "Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Ensure default headers work with multiple field values
    access_headers = {"Authorization": "Bearer {}, Basic creds".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Ensure default headers work with multiple field values in any position
    access_headers = {"Authorization": "Basic creds, Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}


def test_header_with_trailing_spaces_and_commas(app):
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    access_headers = {"Authorization": "Bearer {},   ".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}


def test_custom_header_name(app):
    app.config["JWT_HEADER_NAME"] = "Foo"
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    # Insure 'default' headers no longer work
    access_headers = {"Authorization": "Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing Foo Header"}

    # Insure new headers do work
    access_headers = {"Foo": "Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Ensure new headers work with multiple field values
    access_headers = {"Foo": "Bearer {}, Basic randomcredshere".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Ensure new headers work with multiple field values in any position
    access_headers = {"Foo": "Basic randomcredshere, Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}


def test_custom_header_type(app):
    app.config["JWT_HEADER_TYPE"] = "JWT"
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    # Insure 'default' headers no longer work
    access_headers = {"Authorization": "Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    error_msg = (
        "Missing 'JWT' type in 'Authorization' header. "
        "Expected 'Authorization: JWT <JWT>'"
    )
    assert response.status_code == 401
    assert response.get_json() == {"msg": error_msg}

    # Insure new headers do work
    access_headers = {"Authorization": "JWT {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Ensure new headers work with multiple field values
    access_headers = {"Authorization": "JWT {}, Basic creds".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Ensure new headers work with multiple field values in any position
    access_headers = {"Authorization": "Basic creds, JWT {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Insure new headers without a type also work
    app.config["JWT_HEADER_TYPE"] = ""
    access_headers = {"Authorization": access_token}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Insure header with too many parts fails
    app.config["JWT_HEADER_TYPE"] = ""
    access_headers = {"Authorization": "Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    expected_json = {"msg": "Bad Authorization header. Expected 'Authorization: <JWT>'"}
    assert response.get_json() == expected_json
    assert response.status_code == 422


def test_missing_headers(app):
    test_client = app.test_client()
    jwtM = get_jwt_manager(app)

    # Insure 'default' no headers response
    response = test_client.get("/protected", headers=None)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing Authorization Header"}

    # Test custom no headers response
    @jwtM.unauthorized_loader
    def custom_response(err_str):
        return jsonify(foo="bar"), 201

    response = test_client.get("/protected", headers=None)
    assert response.status_code == 201
    assert response.get_json() == {"foo": "bar"}


def test_header_without_jwt(app):
    test_client = app.test_client()

    access_headers = {"Authorization": "Bearer "}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 422
    assert response.get_json() == {
        "msg": "Bad Authorization header. Expected 'Authorization: Bearer <JWT>'"
    }


def test_custom_error_msg_key(app):
    app.config["JWT_ERROR_MESSAGE_KEY"] = "message"
    response = app.test_client().get("/protected", headers=None)
    assert response.get_json() == {"message": "Missing Authorization Header"}
