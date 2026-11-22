import pytest
from flask import Flask

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "secret"
    JWTManager(app)

    @app.route("/jwt_required", methods=["GET", "OPTIONS"])
    @jwt_required()
    def jwt_required_endpoint():
        return get_jwt_identity() or "ok"

    @app.route("/jwt_optional", methods=["GET", "OPTIONS"])
    @jwt_required(optional=True)
    def jwt_optional_endpoint():
        identity = get_jwt_identity()
        return identity if identity is not None else "none"

    @app.route("/fresh_jwt_required", methods=["GET", "OPTIONS"])
    @jwt_required(fresh=True)
    def fresh_jwt_required_endpoint():
        return "ok"

    @app.route("/jwt_refresh_token_required", methods=["GET", "OPTIONS"])
    @jwt_required(refresh=True)
    def jwt_refresh_token_required_endpoint():
        return "ok"

    return app


def test_access_jwt_required_enpoint(app):
    res = app.test_client().options("/jwt_required")
    assert res.status_code == 200
    assert res.data == b"ok"


def test_access_jwt_optional_endpoint_without_token(app):
    res = app.test_client().options("/jwt_optional")
    assert res.status_code == 200
    assert res.data == b"none"


def test_access_jwt_optional_endpoint_with_token(app):
    with app.test_request_context():
        token = create_access_token(identity="test_user")

    res = app.test_client().options(
        "/jwt_optional", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    assert res.data == b"test_user"


def test_access_jwt_refresh_token_required_enpoint(app):
    res = app.test_client().options("/jwt_refresh_token_required")
    assert res.status_code == 200
    assert res.data == b"ok"


def test_access_fresh_jwt_required_enpoint(app):
    res = app.test_client().options("/fresh_jwt_required")
    assert res.status_code == 200
    assert res.data == b"ok"
