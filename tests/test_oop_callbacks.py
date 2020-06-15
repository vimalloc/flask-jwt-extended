import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager as JWTManager_
from tests.utils import make_headers


class JWTManager(JWTManager_):
    def _user_claims_callback(self, identity):
        return {"foo": "bar"}


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    JWTManager(app)

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def get_claims():
        return jsonify(get_jwt())

    return app


def test_user_claim_in_access_token(app):
    with app.test_request_context():
        access_token = create_access_token("username")

    test_client = app.test_client()
    response = test_client.get("/protected", headers=make_headers(access_token))
    assert response.get_json()["foo"] == "bar"
    assert response.status_code == 200
