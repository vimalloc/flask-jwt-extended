import pytest
from flask import Flask, jsonify

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required,
    create_refresh_token
)
from tests.utils import get_jwt_manager, make_headers


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    app.config['JWT_BLACKLIST_ENABLED'] = True
    JWTManager(app)

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def access_protected():
        return jsonify(foo='bar')

    @app.route('/refresh_protected', methods=['GET'])
    @jwt_refresh_token_required
    def refresh_protected():
        return jsonify(foo='bar')

    return app


@pytest.mark.parametrize("blacklist_type", [['access'], ['refresh', 'access']])
def test_non_blacklisted_access_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return False

    with app.test_request_context():
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("blacklist_type", [['access'], ['refresh', 'access']])
def test_blacklisted_access_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    with app.test_request_context():
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.get_json() == {'msg': 'Token has been revoked'}
    assert response.status_code == 401


@pytest.mark.parametrize("blacklist_type", [['refresh'], ['refresh', 'access']])
def test_non_blacklisted_refresh_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return False

    with app.test_request_context():
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = test_client.get('/refresh_protected', headers=make_headers(refresh_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("blacklist_type", [['refresh'], ['refresh', 'access']])
def test_blacklisted_refresh_token(app, blacklist_type):
    jwt = get_jwt_manager(app)
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = blacklist_type

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    with app.test_request_context():
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = test_client.get('/refresh_protected', headers=make_headers(refresh_token))
    assert response.get_json() == {'msg': 'Token has been revoked'}
    assert response.status_code == 401


def test_no_blacklist_callback_method_provided(app):
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

    with app.test_request_context():
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.status_code == 500


def test_revoked_token_of_different_type(app):
    jwt = get_jwt_manager(app)
    test_client = app.test_client()

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    with app.test_request_context():
        access_token = create_access_token('username')
        refresh_token = create_refresh_token('username')

    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
    response = test_client.get('/refresh_protected', headers=make_headers(refresh_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200

    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['refresh']
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


def test_custom_blacklisted_message(app):
    jwt = get_jwt_manager(app)

    @jwt.token_in_blacklist_loader
    def check_blacklisted(decrypted_token):
        return True

    @jwt.revoked_token_loader
    def custom_error():
        return jsonify(baz='foo'), 404

    with app.test_request_context():
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.get_json() == {'baz': 'foo'}
    assert response.status_code == 404
