import pytest
from flask import Flask, jsonify, json

from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from tests.utils import get_jwt_manager


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    JWTManager(app)

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def access_protected():
        return jsonify(foo='bar')

    return app


def test_custom_header_name(app):
    app.config['JWT_HEADER_NAME'] = 'Foo'
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token('username')

    # Insure 'default' headers no longer work
    access_headers = {'Authorization': 'Bearer {}'.format(access_token)}
    response = test_client.get('/protected', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing Foo Header'}

    # Insure new headers do work
    access_headers = {'Foo': 'Bearer {}'.format(access_token)}
    response = test_client.get('/protected', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}


def test_custom_header_type(app):
    app.config['JWT_HEADER_TYPE'] = 'JWT'
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token('username')

    # Insure 'default' headers no longer work
    access_headers = {'Authorization': 'Bearer {}'.format(access_token)}
    response = test_client.get('/protected', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 422
    assert json_data == {'msg': "Bad Authorization header. Expected value 'JWT <JWT>'"}

    # Insure new headers do work
    access_headers = {'Authorization': 'JWT {}'.format(access_token)}
    response = test_client.get('/protected', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}

    # Insure new headers without a type also work
    app.config['JWT_HEADER_TYPE'] = ''
    access_headers = {'Authorization': access_token}
    response = test_client.get('/protected', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}


def test_missing_headers(app):
    test_client = app.test_client()
    jwtM = get_jwt_manager(app)

    # Insure 'default' no headers response
    response = test_client.get('/protected', headers=None)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': "Missing Authorization Header"}

    # Test custom no headers response
    @jwtM.unauthorized_loader
    def custom_response(err_str):
        return jsonify(foo='bar'), 201

    response = test_client.get('/protected', headers=None)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 201
    assert json_data == {'foo': "bar"}
