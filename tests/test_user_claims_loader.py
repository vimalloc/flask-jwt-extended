import pytest
from flask import Flask, jsonify

from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_claims,
    decode_token, jwt_refresh_token_required, create_refresh_token
)
from tests.utils import get_jwt_manager, make_headers


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    JWTManager(app)

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def get_claims():
        return jsonify(get_jwt_claims())

    @app.route('/protected2', methods=['GET'])
    @jwt_refresh_token_required
    def get_refresh_claims():
        return jsonify(get_jwt_claims())

    return app


def test_user_claim_in_access_token(app):
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    with app.test_request_context():
        access_token = create_access_token('username')

    test_client = app.test_client()
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


def test_non_serializable_user_claims(app):
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return app

    with pytest.raises(TypeError):
        with app.test_request_context():
            create_access_token('username')


def test_token_from_complex_object(app):
    class TestObject:
        def __init__(self, username):
            self.username = username

    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(test_obj):
        return {'username': test_obj.username}

    @jwt.user_identity_loader
    def add_claims(test_obj):
        return test_obj.username

    with app.test_request_context():
        access_token = create_access_token(TestObject('username'))

        # Make sure the changes appear in the token
        decoded_token = decode_token(access_token)
        assert decoded_token['identity'] == 'username'
        assert decoded_token['user_claims'] == {'username': 'username'}

    test_client = app.test_client()
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.get_json() == {'username': 'username'}
    assert response.status_code == 200


def test_user_claims_with_different_name(app):
    jwt = get_jwt_manager(app)
    app.config['JWT_USER_CLAIMS'] = 'banana'

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    with app.test_request_context():
        access_token = create_access_token('username')

        # Make sure the name is actually different in the token
        decoded_token = decode_token(access_token)
        assert decoded_token['banana'] == {'foo': 'bar'}

    # Make sure the correct data is returned to us from the full call
    test_client = app.test_client()
    response = test_client.get('/protected', headers=make_headers(access_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200


def test_user_claim_not_in_refresh_token(app):
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    with app.test_request_context():
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = test_client.get('/protected2', headers=make_headers(refresh_token))
    assert response.get_json() == {}
    assert response.status_code == 200


def test_user_claim_in_refresh_token(app):
    app.config['JWT_CLAIMS_IN_REFRESH_TOKEN'] = True
    jwt = get_jwt_manager(app)

    @jwt.user_claims_loader
    def add_claims(identity):
        return {'foo': 'bar'}

    with app.test_request_context():
        refresh_token = create_refresh_token('username')

    test_client = app.test_client()
    response = test_client.get('/protected2', headers=make_headers(refresh_token))
    assert response.get_json() == {'foo': 'bar'}
    assert response.status_code == 200
