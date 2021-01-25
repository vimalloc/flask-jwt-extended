import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_header
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from tests.utils import get_jwt_manager
from tests.utils import make_headers


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    JWTManager(app)

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def get_claims():
        return jsonify(get_jwt_header())

    @app.route("/protected2", methods=["GET"])
    @jwt_required(refresh=True)
    def get_refresh_claims():
        return jsonify(get_jwt_header())

    return app


def test_jwt_headers_in_access_token(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_headers_loader
    def add_jwt_headers(identity):
        return {"foo": "bar"}

    with app.test_request_context():
        access_token = create_access_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json().get("foo") == "bar"
    assert response.status_code == 200


def test_non_serializable_headers(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_headers_loader
    def add_jwt_headers(identity):
        return app

    with pytest.raises(TypeError):
        with app.test_request_context():
            create_access_token("username")


def test_jwt_headers_in_refresh_token(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_headers_loader
    def add_jwt_headers(identity):
        return {"foo": "bar"}

    with app.test_request_context():
        refresh_token = create_refresh_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected2", headers=make_headers(refresh_token))
    assert response.get_json().get("foo") == "bar"
    assert response.status_code == 200


def test_jwt_header_in_refresh_token_specified_at_creation(app):
    with app.test_request_context():
        refresh_token = create_refresh_token(
            "username", additional_headers={"foo": "bar"}
        )

    test_client = app.test_client()
    response = test_client.get("/protected2", headers=make_headers(refresh_token))
    assert response.get_json().get("foo") == "bar"
    assert response.status_code == 200


def test_jwt_header_in_access_token_specified_at_creation(app):
    with app.test_request_context():
        access_token = create_access_token(
            "username", additional_headers={"foo": "bar"}
        )

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json().get("foo") == "bar"
    assert response.status_code == 200


def test_jwt_header_in_access_token_specified_at_creation_override(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_headers_loader
    def add_jwt_headers(identity):
        return {"ping": "pong"}

    with app.test_request_context():
        access_token = create_access_token(
            "username", additional_headers={"foo": "bar"}
        )

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json().get("foo") == "bar"
    assert response.status_code == 200


def test_jwt_header_in_refresh_token_specified_at_creation_override(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_headers_loader
    def add_jwt_headers(identity):
        return {"ping": "pong"}

    with app.test_request_context():
        access_token = create_refresh_token(
            "username", additional_headers={"foo": "bar"}
        )

    test_client = app.test_client()
    response = test_client.get("/protected2", headers=make_headers(access_token))
    assert response.get_json().get("foo") == "bar"
    assert response.status_code == 200
