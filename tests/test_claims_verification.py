import pytest
from flask import Flask
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from tests.utils import get_jwt_manager
from tests.utils import make_headers


@pytest.fixture(scope="function")
def app():
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = "foobarbaz"
    jwt = JWTManager(app)

    @jwt.user_claims_loader
    def add_user_claims(identity):
        return {"foo": "bar"}

    @app.route("/protected1", methods=["GET"])
    @jwt_required()
    def protected1():
        return jsonify(foo="bar")

    @app.route("/protected2", methods=["GET"])
    @jwt_required(fresh=True)
    def protected2():
        return jsonify(foo="bar")

    @app.route("/protected3", methods=["GET"])
    @jwt_required(optional=True)
    def protected3():
        return jsonify(foo="bar")

    return app


@pytest.mark.parametrize("url", ["/protected1", "/protected2", "/protected3"])
def test_successful_claims_validation(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def claims_verification_callback(token):
        return token["foo"] == "bar"

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username", fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json()["foo"] == "bar"
    assert response.status_code == 200


@pytest.mark.parametrize("url", ["/protected1", "/protected2", "/protected3"])
def test_unsuccessful_claims_validation(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def claim_verification_callback(user_claims):
        return False

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username", fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {"msg": "User claims verification failed"}
    assert response.status_code == 400


@pytest.mark.parametrize("url", ["/protected1", "/protected2", "/protected3"])
def test_claims_validation_custom_error(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def claims_verification_callback(user_claims):
        return False

    @jwt.claims_verification_failed_loader
    def custom_error(jwt_header, jwt_data):
        assert jwt_header["alg"] == "HS256"
        assert jwt_data["sub"] == "username"
        user = get_jwt_identity()
        return jsonify(msg="claims failed for {}".format(user)), 404

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username", fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {"msg": "claims failed for username"}
    assert response.status_code == 404


@pytest.mark.parametrize("url", ["/protected1", "/protected2", "/protected3"])
def test_get_token_identity_in_verification_method(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def claim_verification_callback(token):
        # Make sure that we can get the jwt identity in here if we need it.
        user = get_jwt_identity()
        return user == "username"

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token("username", fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {"foo": "bar"}
    assert response.status_code == 200
