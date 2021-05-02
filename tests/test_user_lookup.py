import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import get_current_user
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from tests.utils import get_jwt_manager
from tests.utils import make_headers


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    JWTManager(app)

    @app.route("/get_user1", methods=["GET"])
    @jwt_required()
    def get_user1():
        try:
            return jsonify(foo=get_current_user()["username"])
        except RuntimeError as e:
            return jsonify(error=str(e))

    @app.route("/get_user2", methods=["GET"])
    @jwt_required()
    def get_user2():
        try:
            return jsonify(foo=current_user["username"])
        except RuntimeError as e:
            return jsonify(error=str(e))

    return app


@pytest.mark.parametrize("url", ["/get_user1", "/get_user2"])
def test_no_user_lookup_loader_specified(app, url):
    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")

    response = test_client.get(url, headers=make_headers(access_token))
    assert "@jwt.user_lookup_loader" in response.get_json()["error"]


@pytest.mark.parametrize("url", ["/get_user1", "/get_user2"])
def test_load_valid_user(app, url):
    jwt = get_jwt_manager(app)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        return {"username": jwt_data["sub"]}

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 200
    assert response.get_json() == {"foo": "username"}


@pytest.mark.parametrize("url", ["/get_user1", "/get_user2"])
def test_load_invalid_user(app, url):
    jwt = get_jwt_manager(app)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        return None

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Error loading the user username"}


@pytest.mark.parametrize("url", ["/get_user1", "/get_user2"])
def test_custom_user_lookup_errors(app, url):
    jwt = get_jwt_manager(app)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        return None

    @jwt.user_lookup_error_loader
    def user_lookup_error(jwt_header, jwt_data):
        assert jwt_header["alg"] == "HS256"
        assert jwt_data["sub"] == "username"
        return jsonify(foo="bar"), 201

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username")

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 201
    assert response.get_json() == {"foo": "bar"}
