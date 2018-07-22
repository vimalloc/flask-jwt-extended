import pytest
from flask import Flask, jsonify

from flask_jwt_extended import (
    JWTManager, jwt_required, jwt_refresh_token_required, create_access_token,
    create_refresh_token
)
from tests.utils import get_jwt_manager


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    app.config['JWT_TOKEN_LOCATION'] = 'json'
    JWTManager(app)

    @app.route('/protected', methods=['POST'])
    @jwt_required
    def access_protected():
        return jsonify(foo='bar')

    @app.route('/refresh', methods=['POST'])
    @jwt_refresh_token_required
    def refresh_protected():
        return jsonify(foo='bar')

    return app


def test_content_type(app):
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token('username')
        refresh_token = create_refresh_token('username')

    data = {'access_token': access_token}
    response = test_client.post('/protected', data=data)
    expected_json = {'msg': 'Invalid content-type. Must be application/json.'}
    assert response.status_code == 401
    assert response.get_json() == expected_json

    data = {'refresh_token': refresh_token}
    response = test_client.post('/refresh', data=data)
    expected_json = {'msg': 'Invalid content-type. Must be application/json.'}
    assert response.status_code == 401
    assert response.get_json() == expected_json


def test_custom_body_key(app):
    app.config['JWT_JSON_KEY'] = 'Foo'
    app.config['JWT_REFRESH_JSON_KEY'] = 'Bar'
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token('username')
        refresh_token = create_refresh_token('username')

    # Ensure 'default' keys no longer work
    data = {'access_token': access_token}
    response = test_client.post('/protected', json=data)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing "Foo" key in json data.'}

    data = {'refresh_token': refresh_token}
    response = test_client.post('/refresh', json=data)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing "Bar" key in json data.'}

    # Ensure new keys do work
    data = {'Foo': access_token}
    response = test_client.post('/protected', json=data)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    data = {'Bar': refresh_token}
    response = test_client.post('/refresh', json=data)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}


def test_missing_keys(app):
    test_client = app.test_client()
    jwtM = get_jwt_manager(app)
    headers = {'content-type': 'application/json'}

    # Ensure 'default' no json response
    response = test_client.post('/protected', headers=headers)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing "access_token" key in json data.'}

    # Test custom no json response
    @jwtM.unauthorized_loader
    def custom_response(err_str):
        return jsonify(foo='bar'), 201

    response = test_client.post('/protected', headers=headers)
    assert response.status_code == 201
    assert response.get_json() == {'foo': "bar"}


def test_defaults(app):
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token('username')
        refresh_token = create_refresh_token('username')

    data = {'access_token': access_token}
    response = test_client.post('/protected', json=data)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    data = {'refresh_token': refresh_token}
    response = test_client.post('/refresh', json=data)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}
