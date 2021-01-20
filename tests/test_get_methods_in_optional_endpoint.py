import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import current_user
from flask_jwt_extended import get_current_user
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_header
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    jwt = JWTManager(app)

    @app.route("/optional", methods=["GET"])
    @jwt_required(optional=True)
    def access_protected():
        assert get_jwt() == {}
        assert get_jwt_header() == {}
        assert get_jwt_identity() == None  # noqa: E711
        assert get_current_user() == None  # noqa: E711
        assert current_user == None  # noqa: E711
        return jsonify(foo="bar")

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, _jwt_data):
        assert True == False  # noqa: E712

    return app


def test_get_jwt_in_optional_route(app):
    test_client = app.test_client()
    response = test_client.get("/optional")
    assert response.status_code == 200
    assert response.get_json() == {"foo": "bar"}
