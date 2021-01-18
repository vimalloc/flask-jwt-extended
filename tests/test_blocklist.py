import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from tests.utils import get_jwt_manager
from tests.utils import make_headers


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    app.config["JWT_BLOCKLIST_ENABLED"] = True
    JWTManager(app)

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def access_protected():
        return jsonify(foo="bar")

    @app.route("/refresh_protected", methods=["GET"])
    @jwt_required(refresh=True)
    def refresh_protected():
        return jsonify(foo="bar")

    return app


@pytest.mark.parametrize("blocklist_type", [["access"], ["refresh", "access"]])
def test_non_blocklisted_access_token(app, blocklist_type):
    jwt = get_jwt_manager(app)
    app.config["JWT_BLOCKLIST_TOKEN_CHECKS"] = blocklist_type

    @jwt.token_in_blocklist_loader
    def check_blocklisted(decrypted_token):
        return False

    with app.test_request_context():
        access_token = create_access_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json() == {"foo": "bar"}
    assert response.status_code == 200


@pytest.mark.parametrize("blocklist_type", [["access"], ["refresh", "access"]])
def test_blocklisted_access_token(app, blocklist_type):
    jwt = get_jwt_manager(app)
    app.config["JWT_BLOCKLIST_TOKEN_CHECKS"] = blocklist_type

    @jwt.token_in_blocklist_loader
    def check_blocklisted(decrypted_token):
        return True

    with app.test_request_context():
        access_token = create_access_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json() == {"msg": "Token has been revoked"}
    assert response.status_code == 401


@pytest.mark.parametrize("blocklist_type", [["refresh"], ["refresh", "access"]])
def test_non_blocklisted_refresh_token(app, blocklist_type):
    jwt = get_jwt_manager(app)
    app.config["JWT_BLOCKLIST_TOKEN_CHECKS"] = blocklist_type

    @jwt.token_in_blocklist_loader
    def check_blocklisted(decrypted_token):
        return False

    with app.test_request_context():
        refresh_token = create_refresh_token("username")

    test_client = app.test_client()
    response = test_client.get(
        "/refresh_protected", headers=make_headers(refresh_token)
    )
    assert response.get_json() == {"foo": "bar"}
    assert response.status_code == 200


@pytest.mark.parametrize("blocklist_type", [["refresh"], ["refresh", "access"]])
def test_blocklisted_refresh_token(app, blocklist_type):
    jwt = get_jwt_manager(app)
    app.config["JWT_BLOCKLIST_TOKEN_CHECKS"] = blocklist_type

    @jwt.token_in_blocklist_loader
    def check_blocklisted(decrypted_token):
        return True

    with app.test_request_context():
        refresh_token = create_refresh_token("username")

    test_client = app.test_client()
    response = test_client.get(
        "/refresh_protected", headers=make_headers(refresh_token)
    )
    assert response.get_json() == {"msg": "Token has been revoked"}
    assert response.status_code == 401


def test_no_blocklist_callback_method_provided(app):
    app.config["JWT_BLOCKLIST_TOKEN_CHECKS"] = ["access"]

    with app.test_request_context():
        access_token = create_access_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.status_code == 500


def test_revoked_token_of_different_type(app):
    jwt = get_jwt_manager(app)
    test_client = app.test_client()

    @jwt.token_in_blocklist_loader
    def check_blocklisted(decrypted_token):
        return True

    with app.test_request_context():
        access_token = create_access_token("username")
        refresh_token = create_refresh_token("username")

    app.config["JWT_BLOCKLIST_TOKEN_CHECKS"] = ["access"]
    response = test_client.get(
        "/refresh_protected", headers=make_headers(refresh_token)
    )
    assert response.get_json() == {"foo": "bar"}
    assert response.status_code == 200

    app.config["JWT_BLOCKLIST_TOKEN_CHECKS"] = ["refresh"]
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json() == {"foo": "bar"}
    assert response.status_code == 200


def test_custom_blocklisted_message(app):
    jwt = get_jwt_manager(app)

    @jwt.token_in_blocklist_loader
    def check_blocklisted(decrypted_token):
        return True

    @jwt.revoked_token_loader
    def custom_error(jwt_header, jwt_data):
        assert jwt_header["alg"] == "HS256"
        assert jwt_data["sub"] == "username"
        return jsonify(baz="foo"), 404

    with app.test_request_context():
        access_token = create_access_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json() == {"baz": "foo"}
    assert response.status_code == 404
