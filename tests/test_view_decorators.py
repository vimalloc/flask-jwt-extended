import pytest
from datetime import timedelta
from flask import Flask, jsonify

from flask_jwt_extended import (
    jwt_required, fresh_jwt_required, JWTManager, jwt_refresh_token_required,
    jwt_optional, create_access_token, create_refresh_token, get_jwt_identity
)
from tests.utils import make_headers, encode_token, get_jwt_manager


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
        assert response.status_code == 200
        assert response.get_json() == {'foo': 'bar'}

    # Test accessing jwt_required with no jwt in the request
    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing Authorization Header'}

    # Test refresh token access to jwt_required
    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Only access tokens are allowed'}


def test_fresh_jwt_required(app):
    jwtM = get_jwt_manager(app)
    url = '/fresh_protected'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')
        fresh_access_token = create_access_token('username', fresh=True)
        refresh_token = create_refresh_token('username')
        fresh_timed_access_token = create_access_token(
            identity='username',
            fresh=timedelta(minutes=5)
        )
        stale_timed_access_token = create_access_token(
            identity='username',
            fresh=timedelta(minutes=-1)
        )

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Fresh token required'}

    response = test_client.get(url, headers=make_headers(fresh_timed_access_token))
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    response = test_client.get(url, headers=make_headers(stale_timed_access_token))
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Fresh token required'}

    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing Authorization Header'}

    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Only access tokens are allowed'}

    # Test with custom response
    @jwtM.needs_fresh_token_loader
    def custom_response():
        return jsonify(msg='foobar'), 201

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 201
    assert response.get_json() == {'msg': 'foobar'}


def test_refresh_jwt_required(app):
    url = '/refresh_protected'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')
        fresh_access_token = create_access_token('username', fresh=True)
        refresh_token = create_refresh_token('username')

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Only refresh tokens are allowed'}

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Only refresh tokens are allowed'}

    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing Authorization Header'}

    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}


def test_jwt_optional(app):
    url = '/optional_protected'

    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')
        fresh_access_token = create_access_token('username', fresh=True)
        refresh_token = create_refresh_token('username')
        expired_token = create_access_token(
            identity='username',
            expires_delta=timedelta(minutes=-1)
        )

    response = test_client.get(url, headers=make_headers(fresh_access_token))
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'baz'}

    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'baz'}

    response = test_client.get(url, headers=make_headers(refresh_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Only access tokens are allowed'}

    response = test_client.get(url, headers=None)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    response = test_client.get(url, headers=make_headers(expired_token))
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Token has expired'}


def test_invalid_jwt(app):
    url = '/protected'
    jwtM = get_jwt_manager(app)
    test_client = app.test_client()
    invalid_token = "aaaaa.bbbbb.ccccc"

    # Test default response
    response = test_client.get(url, headers=make_headers(invalid_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Invalid header padding'}

    # Test custom response
    @jwtM.invalid_token_loader
    def custom_response(err_str):
        return jsonify(msg='foobar'), 201

    response = test_client.get(url, headers=make_headers(invalid_token))
    assert response.status_code == 201
    assert response.get_json() == {'msg': 'foobar'}


def test_jwt_missing_claims(app):
    url = '/protected'
    test_client = app.test_client()
    token = encode_token(app, {'foo': 'bar'})

    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Missing claim: identity'}


def test_jwt_invalid_audience(app):
    url = '/protected'
    jwtM = get_jwt_manager(app)
    test_client = app.test_client()

    # No audience claim expected or provided - OK
    access_token = encode_token(app, {'identity': 'me'})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 200

    # Audience claim expected and not provided - not OK
    app.config['JWT_DECODE_AUDIENCE'] = 'my_audience'
    access_token = encode_token(app, {'identity': 'me'})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Token is missing the "aud" claim'}

    # Audience claim still expected and wrong one provided - not OK
    access_token = encode_token(app, {'aud': 'different_audience', 'identity': 'me'})
    response = test_client.get(url, headers=make_headers(access_token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'Invalid audience'}


def test_expired_token(app):
    url = '/protected'
    jwtM = get_jwt_manager(app)
    test_client = app.test_client()
    with app.test_request_context():
        token = create_access_token('username', expires_delta=timedelta(minutes=-1))

    # Test default response
    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Token has expired'}

    # Test custom response
    @jwtM.expired_token_loader
    def custom_response():
        return jsonify(msg='foobar'), 201

    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 201
    assert response.get_json() == {'msg': 'foobar'}


def test_no_token(app):
    url = '/protected'
    jwtM = get_jwt_manager(app)
    test_client = app.test_client()

    # Test default response
    response = test_client.get(url, headers=None)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing Authorization Header'}

    # Test custom response
    @jwtM.unauthorized_loader
    def custom_response(err_str):
        return jsonify(msg='foobar'), 201

    response = test_client.get(url, headers=None)
    assert response.status_code == 201
    assert response.get_json() == {'msg': 'foobar'}


def test_different_token_algorightm(app):
    url = '/protected'
    test_client = app.test_client()
    with app.test_request_context():
        token = create_access_token('username')

    app.config['JWT_ALGORITHM'] = 'HS512'

    response = test_client.get(url, headers=make_headers(token))
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'The specified alg value is not allowed'}
