import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import decode_token
from flask_jwt_extended import get_jwt
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
        return jsonify(get_jwt())

    @app.route("/protected2", methods=["GET"])
    @jwt_required(refresh=True)
    def get_refresh_claims():
        return jsonify(get_jwt())

    return app


def test_additional_claims_in_access_token(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_claims_loader
    def add_claims(identity):
        return {"foo": "bar"}

    with app.test_request_context():
        access_token = create_access_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json()["foo"] == "bar"
    assert response.status_code == 200


def test_non_serializable_claims(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_claims_loader
    def add_claims(identity):
        return app

    with pytest.raises(TypeError):
        with app.test_request_context():
            create_access_token("username")


def test_token_from_complex_object(app):
    class TestObject:  # noqa: B903
        def __init__(self, username):
            self.username = username

    jwt = get_jwt_manager(app)

    @jwt.additional_claims_loader
    def add_claims(test_obj):
        return {"username": test_obj.username}

    @jwt.user_identity_loader
    def add_identity(test_obj):
        return test_obj.username

    with app.test_request_context():
        access_token = create_access_token(TestObject("username"))

        # Make sure the changes appear in the token
        decoded_token = decode_token(access_token)
        assert decoded_token["sub"] == "username"
        assert decoded_token["username"] == "username"

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json()["username"] == "username"
    assert response.status_code == 200


def test_additional_claims_in_refresh_token(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_claims_loader
    def add_claims(identity):
        return {"foo": "bar"}

    with app.test_request_context():
        refresh_token = create_refresh_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected2", headers=make_headers(refresh_token))
    assert response.get_json()["foo"] == "bar"
    assert response.status_code == 200


def test_additional_claims_in_refresh_token_specified_at_creation(app):
    with app.test_request_context():
        refresh_token = create_refresh_token(
            "username", additional_claims={"foo": "bar"}
        )

    test_client = app.test_client()
    response = test_client.get("/protected2", headers=make_headers(refresh_token))
    assert response.get_json()["foo"] == "bar"
    assert response.status_code == 200


def test_additional_claims_in_access_token_specified_at_creation(app):
    with app.test_request_context():
        access_token = create_access_token("username", additional_claims={"foo": "bar"})

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json()["foo"] == "bar"
    assert response.status_code == 200


def test_addition_claims_merge(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_claims_loader
    def add_claims(identity):
        return {"default": "value"}

    with app.test_request_context():
        access_token = create_access_token("username", additional_claims={"foo": "bar"})

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json()["foo"] == "bar"
    assert response.get_json()["default"] == "value"
    assert response.status_code == 200


def test_addition_claims_merge_tie_goes_to_create_access_token(app):
    jwt = get_jwt_manager(app)

    @jwt.additional_claims_loader
    def add_claims(identity):
        return {"default": "value"}

    with app.test_request_context():
        access_token = create_access_token(
            "username", additional_claims={"default": "foo"}
        )

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json()["default"] == "foo"
    assert response.status_code == 200
