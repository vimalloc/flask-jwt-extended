import pytest
from datetime import timedelta
from flask import Flask, jsonify, json

from flask_jwt_extended import (
    jwt_required, fresh_jwt_required, JWTManager, jwt_refresh_token_required,
    jwt_optional, create_access_token, create_refresh_token, get_jwt_identity
)
from tests.utils import make_headers


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    JWTManager(app)

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def protected():
        return jsonify(foo='bar')

    @app.route('/fresh_protected', methods=['GET'])
    @fresh_jwt_required
    def fresh_protected():
        return jsonify(foo='bar')

    @app.route('/refresh_protected', methods=['GET'])
    @jwt_refresh_token_required
    def refresh_protected():
        return jsonify(foo='bar')

    @app.route('/optional_protected', methods=['GET'])
    @jwt_optional
    def optional_protected():
        if get_jwt_identity():
            return jsonify(foo='baz')
        else:
            return jsonify(foo='bar')

    return app


def test_jwt_required(app):
    url = '/protected'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')
        fresh_access_token = create_access_token('username', fresh=True)
        refresh_token = create_refresh_token('username')

    # Access and fresh access should be able to access this
    for token in (access_token, fresh_access_token):
        response = test_client.get(url, headers=make_headers(token))
        json_data = json.loads(response.get_data(as_text=True))
        assert response.status_code == 200
        assert json_data == {'foo': 'bar'}

    # Test accessing jwt_required with no jwt in the request
    response = test_client.get(url, headers=None)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing Authorization Header'}

    # Test refresh token access to jwt_required
    response = test_client.get(url, headers=make_headers(refresh_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 422
    assert json_data == {'msg': 'Only access tokens can access this endpoint'}


def test_fresh_jwt_required(app):
    url = '/fresh_protected'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')
        fresh_access_token = create_access_token('username', fresh=True)
        refresh_token = create_refresh_token('username')

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}

    response = test_client.get(url, headers=make_headers(access_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Fresh token required'}

    response = test_client.get(url, headers=None)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing Authorization Header'}

    response = test_client.get(url, headers=make_headers(refresh_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 422
    assert json_data == {'msg': 'Only access tokens can access this endpoint'}


def test_refresh_jwt_required(app):
    url = '/refresh_protected'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')
        fresh_access_token = create_access_token('username', fresh=True)
        refresh_token = create_refresh_token('username')

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 422
    assert json_data == {'msg': 'Only refresh tokens can access this endpoint'}

    response = test_client.get(url, headers=make_headers(access_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 422
    assert json_data == {'msg': 'Only refresh tokens can access this endpoint'}

    response = test_client.get(url, headers=None)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing Authorization Header'}

    response = test_client.get(url, headers=make_headers(refresh_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}


def test_jwt_optional(app):
    url = '/optional_protected'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')
        fresh_access_token = create_access_token('username', fresh=True)
        expired_token = create_access_token('username', expires_delta=timedelta(minutes=-1))
        refresh_token = create_refresh_token('username')

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'baz'}

    response = test_client.get(url, headers=make_headers(access_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'baz'}

    response = test_client.get(url, headers=make_headers(refresh_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 422
    assert json_data == {'msg': 'Only access tokens can access this endpoint'}

    response = test_client.get(url, headers=None)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}

    response = test_client.get(url, headers=make_headers(expired_token))
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Token has expired'}

# TODO test different header name and type
# TODO test asymmetric crypto
# TODO test different name for user claims key in dict
