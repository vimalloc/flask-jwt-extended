import pytest
from flask import Flask

from flask_jwt_extended import current_user
from flask_jwt_extended import get_current_user
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_header
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import JWTManager


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    JWTManager(app)
    return app


def test_get_jwt_in_non_protected_route(app):
    with app.test_request_context():
        with pytest.raises(RuntimeError):
            get_jwt()


def test_get_jwt_header_in_non_protected_route(app):
    with app.test_request_context():
        with pytest.raises(RuntimeError):
            get_jwt_header()


def test_get_jwt_identity_in_non_protected_route(app):
    with app.test_request_context():
        with pytest.raises(RuntimeError):
            get_jwt_identity()


def test_current_user_in_non_protected_route(app):
    with app.test_request_context():
        with pytest.raises(RuntimeError):
            current_user.foo


def test_get_current_user_in_non_protected_route(app):
    with app.test_request_context():
        with pytest.raises(RuntimeError):
            get_current_user()
