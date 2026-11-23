import pytest
from flask import Flask, jsonify

from flask_jwt_extended import (
    JWTManager,
    current_user,
    get_current_user,
    get_jwt,
    get_jwt_header,
    get_jwt_identity,
    jwt_required,
)
from tests.utils import JWT_SECRET_KEY


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
    jwt = JWTManager(app)

    @app.route("/optional", methods=["GET"])
    @jwt_required(optional=True)
    def access_protected():
        assert get_jwt() == {}
        assert get_jwt_header() == {}
        assert get_jwt_identity() == None
        assert get_current_user() == None
        assert current_user == None
        return jsonify(foo="bar")

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, _jwt_data):
        raise RuntimeError("test failed")

    return app


def test_get_jwt_in_optional_route(app):
    test_client = app.test_client()
    response = test_client.get("/optional")
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}
