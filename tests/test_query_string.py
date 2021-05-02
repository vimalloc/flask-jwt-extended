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
    app.config["JWT_TOKEN_LOCATION"] = ["query_string"]
    JWTManager(app)

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def access_protected():
        return jsonify(foo="bar")

    return app


def test_default_query_paramater(app):
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    url = "/protected?jwt={}".format(access_token)
    response = test_client.get(url)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}


def test_query_string_value_prefix(app):
    app.config["JWT_QUERY_STRING_VALUE_PREFIX"] = "bearer "
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    # Valid string prefix
    url = f"/protected?jwt=bearer {access_token}"
    response = test_client.get(url)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}

    # Invalid string prefix
    url = f"/protected?jwt={access_token}"
    response = test_client.get(url)
    error_msg = (
        "Invalid value for query parameter 'jwt'. "
        "Expected the value to start with 'bearer '"
    )
    assert response.status_code == 422
    assert response.get_json() == {"msg": error_msg}


def test_custom_query_paramater(app):
    app.config["JWT_QUERY_STRING_NAME"] = "foo"
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token("username")

    # Insure 'default' query paramaters no longer work
    url = "/protected?jwt={}".format(access_token)
    response = test_client.get(url)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing 'foo' query paramater"}

    # Insure new query_string does work
    url = "/protected?foo={}".format(access_token)
    response = test_client.get(url)
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}


def test_missing_query_paramater(app):
    test_client = app.test_client()
    jwtM = get_jwt_manager(app)

    with app.test_request_context():
        access_token = create_access_token("username")

    # Insure no query paramaters doesn't give a response
    response = test_client.get("/protected")
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing 'jwt' query paramater"}

    # Insure headers don't work
    access_headers = {"Authorization": "Bearer {}".format(access_token)}
    response = test_client.get("/protected", headers=access_headers)
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Missing 'jwt' query paramater"}

    # Test custom response works
    @jwtM.unauthorized_loader
    def custom_response(err_str):
        return jsonify(foo="bar"), 201

    response = test_client.get("/protected")
    assert response.status_code == 201
    assert response.get_json() == {"foo": "bar"}
