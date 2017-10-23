import pytest
from flask import Flask, jsonify, json

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, set_access_cookies
)


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
    JWTManager(app)

    @app.route('/cookie_login', methods=['GET'])
    def cookie_login():
        resp = jsonify(login=True)
        access_token = create_access_token('username')
        set_access_cookies(resp, access_token)
        return resp

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def access_protected():
        return jsonify(foo='bar')

    return app


def test_header_access(app):
    test_client = app.test_client()
    with app.test_request_context():
        access_token = create_access_token('username')

    access_headers = {'Authorization': 'Bearer {}'.format(access_token)}
    response = test_client.get('/protected', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}


def test_cookie_access(app):
    test_client = app.test_client()
    test_client.get('/cookie_login')
    response = test_client.get('/protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}


def test_no_jwt_in_request(app):
    test_client = app.test_client()
    response = test_client.get('/protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing JWT in headers and cookies'}
