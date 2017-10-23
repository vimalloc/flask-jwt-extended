import pytest
from flask import Flask, jsonify, json
from werkzeug.http import parse_cookie

from flask_jwt_extended import (
    jwt_required, JWTManager, jwt_refresh_token_required, create_access_token,
    create_refresh_token, set_access_cookies, set_refresh_cookies,
    unset_jwt_cookies
)
from flask_jwt_extended.config import config


def _get_jwt_from_response_cookie(response, cookie_name):
    cookies = response.headers.getlist('Set-Cookie')
    for cookie in cookies:
        parsed_cookie = parse_cookie(cookie)
        for c_key, c_val in parsed_cookie.items():
            if c_key == cookie_name:
                return c_val
    raise Exception('jwt cooke value not found')


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    JWTManager(app)

    @app.route('/access_token', methods=['GET'])
    def access_token():
        resp = jsonify(login=True)
        access_token = create_access_token('username')
        set_access_cookies(resp, access_token)
        return resp

    @app.route('/refresh_token', methods=['GET'])
    def refresh_token():
        resp = jsonify(login=True)
        refresh_token = create_refresh_token('username')
        set_refresh_cookies(resp, refresh_token)
        return resp

    @app.route('/delete_tokens', methods=['GET'])
    def delete_tokens():
        resp = jsonify(logout=True)
        unset_jwt_cookies(resp)
        return resp

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def protected():
        return jsonify(foo='bar')

    @app.route('/refresh_protected', methods=['GET'])
    @jwt_refresh_token_required
    def refresh_protected():
        return jsonify(foo='bar')

    return app


def test_jwt_required_with_valid_cookies(app):
    test_client = app.test_client()

    # Test without cookies
    response = test_client.get('/protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing cookie "access_token_cookie"'}

    # Test after receiving cookies
    test_client.get('/access_token')
    response = test_client.get('/protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}

    # Test after issuing a 'logout' to delete the cookies
    test_client.get('/delete_tokens')
    response = test_client.get('/protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing cookie "access_token_cookie"'}


def test_jwt_refresh_required_with_cookies(app):
    test_client = app.test_client()

    # Test without cookies
    response = test_client.get('/refresh_protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing cookie "refresh_token_cookie"'}

    # Test after receiving cookies
    test_client.get('/refresh_token')
    response = test_client.get('/refresh_protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}

    # Test after issuing a 'logout' to delete the cookies
    test_client.get('/delete_tokens')
    response = test_client.get('/protected')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 401
    assert json_data == {'msg': 'Missing cookie "access_token_cookie"'}


def test_setting_cookies_wihout_cookies_enabled(app):
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    test_client = app.test_client()

    with pytest.raises(RuntimeWarning):
        test_client.get('/access_token')
    with pytest.raises(RuntimeWarning):
        test_client.get('/refresh_token')
    with pytest.raises(RuntimeWarning):
        test_client.get('/delete_tokens')


def test_custom_cookie_options(app):
    # Test the default options on the received cookies
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_foo'
    app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_foo'
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/protected'
    app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh_protected'
    app.config['JWT_COOKIE_SECURE'] = True
    app.config['JWT_COOKIE_DOMAIN'] = 'test.com'
    app.config['JWT_SESSION_COOKIE'] = False
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False

    # Test the updated options on the received cookies
    pass

# TODO test csrf with multi methods
# TODO test different cookie names
