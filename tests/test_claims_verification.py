import pytest
from flask import Flask, jsonify

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity,
    fresh_jwt_required, jwt_optional
)
from tests.utils import get_jwt_manager, make_headers


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    jwt = JWTManager(app)

    @jwt.user_claims_loader
    def add_user_claims(identity):
        return {'foo': 'bar'}

    @app.route('/protected1', methods=['GET'])
    @jwt_required
    def protected1():
        return jsonify(foo='bar')

    @app.route('/protected2', methods=['GET'])
    @fresh_jwt_required
    def protected2():
        return jsonify(foo='bar')

    @app.route('/protected3', methods=['GET'])
    @jwt_optional
    def protected3():
        return jsonify(foo='bar')

    return app


@pytest.mark.parametrize("url", ['/protected1', '/protected2', '/protected3'])
def test_successful_claims_validation(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def user_load_callback(user_claims):
        return user_claims == {'foo': 'bar'}

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username', fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("url", ['/protected1', '/protected2', '/protected3'])
def test_unsuccessful_claims_validation(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def user_load_callback(user_claims):
        return False

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username', fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {'msg': 'User claims verification failed'}
    assert response.status_code == 400


@pytest.mark.parametrize("url", ['/protected1', '/protected2', '/protected3'])
def test_claims_validation_custom_error(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def user_load_callback(user_claims):
        return False

    @jwt.claims_verification_failed_loader
    def custom_error():
        # Make sure that we can get the jwt identity in here if we need it.
        user = get_jwt_identity()
        return jsonify(msg='claims failed for {}'.format(user)), 404

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username', fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {'msg': 'claims failed for username'}
    assert response.status_code == 404


@pytest.mark.parametrize("url", ['/protected1', '/protected2', '/protected3'])
def test_get_jwt_identity_in_verification_method(app, url):
    jwt = get_jwt_manager(app)

    @jwt.claims_verification_loader
    def user_load_callback(user_claims):
        # Make sure that we can get the jwt identity in here if we need it.
        user = get_jwt_identity()
        return user == 'username'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username', fresh=True)

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200
