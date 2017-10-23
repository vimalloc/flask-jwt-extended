import pytest
from flask import Flask, jsonify, json
from werkzeug.http import parse_cookie

from flask_jwt_extended import (
    jwt_required, JWTManager, jwt_refresh_token_required, create_access_token,
    create_refresh_token, set_access_cookies, set_refresh_cookies,
    unset_jwt_cookies
)
from flask_jwt_extended.config import config


def _get_cookie_from_response(response, cookie_name):
    cookies = response.headers.getlist('Set-Cookie')
    for cookie in cookies:
        parsed_cookie = parse_cookie(cookie)
        if cookie_name in parsed_cookie:
            return parsed_cookie
    return None


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


def test_default_cookie_options(app):
    test_client = app.test_client()

    # Test the default access cookies
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value
    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    access_csrf_cookie = _get_cookie_from_response(response, 'csrf_access_token')
    assert 'access_token_cookie' in access_cookie
    assert access_cookie['HttpOnly; Path'] == '/'
    assert 'csrf_access_token' in access_csrf_cookie

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value
    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    refresh_csrf_cookie = _get_cookie_from_response(response, 'csrf_refresh_token')
    assert 'refresh_token_cookie' in refresh_cookie
    assert 'HttpOnly; Path' in refresh_cookie
    assert refresh_cookie['HttpOnly; Path'] == '/'
    assert 'csrf_refresh_token' in refresh_csrf_cookie


def test_custom_cookie_options(app):
    test_client = app.test_client()

    app.config['JWT_COOKIE_SECURE'] = True
    app.config['JWT_COOKIE_DOMAIN'] = 'test.com'
    app.config['JWT_SESSION_COOKIE'] = False

    # Test access cookies with changed options
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    assert 'access_token_cookie' in access_cookie
    assert 'Domain' in access_cookie
    assert 'Expires=' in str(cookies[0])  # Ignored by parse_cookie :(
    assert 'Secure; HttpOnly; Path' in access_cookie
    assert access_cookie['Domain'] == 'test.com'
    assert access_cookie['Secure; HttpOnly; Path'] == '/'

    access_csrf_cookie = _get_cookie_from_response(response, 'csrf_access_token')
    assert 'csrf_access_token' in access_csrf_cookie
    assert 'Domain' in access_csrf_cookie
    assert 'Expires=' in str(cookies[1])  # Ignored by parse_cookie :(
    assert 'Secure; Path' in access_csrf_cookie
    assert access_csrf_cookie['Domain'] == 'test.com'
    assert access_csrf_cookie['Secure; Path'] == '/'

    # Test refresh cookies with changed options
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    assert 'refresh_token_cookie' in refresh_cookie
    assert 'Domain' in refresh_cookie
    assert 'Expires=' in str(cookies[0])  # Ignored by parse_cookie :(
    assert 'Secure; HttpOnly; Path' in refresh_cookie
    assert refresh_cookie['Domain'] == 'test.com'
    assert refresh_cookie['Secure; HttpOnly; Path'] == '/'

    refresh_csrf_cookie = _get_cookie_from_response(response, 'csrf_refresh_token')
    assert 'csrf_refresh_token' in refresh_csrf_cookie
    assert 'Domain' in refresh_csrf_cookie
    assert 'Expires=' in str(cookies[1])  # Ignored by parse_cookie :(
    assert 'Secure; Path' in refresh_csrf_cookie
    assert refresh_csrf_cookie['Domain'] == 'test.com'
    assert refresh_csrf_cookie['Secure; Path'] == '/'


def test_custom_cookie_names_and_paths(app):
    test_client = app.test_client()

    app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'access_foo_csrf'
    app.config['JWT_REFRESH_CSRF_COOKIE_NAME'] = 'refresh_foo_csrf'
    app.config['JWT_ACCESS_CSRF_COOKIE_PATH'] = '/protected'
    app.config['JWT_REFRESH_CSRF_COOKIE_PATH'] = '/refresh_protected'
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_foo'
    app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_foo'
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/protected'
    app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh_protected'

    # Test the default access cookies
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    access_cookie = _get_cookie_from_response(response, 'access_foo')
    access_csrf_cookie = _get_cookie_from_response(response, 'access_foo_csrf')
    assert 'access_foo' in access_cookie
    assert 'access_foo_csrf' in access_csrf_cookie

    # The parse cookie library ignores 'Path' cookies, and we don't know which
    # cookie in the list is the csrf cookie and which is the jwt cookie. So
    # we have to resort to doing string comparisons on both of them.
    assert 'Path=/protected' in cookies[0]
    assert 'Path=/protected' in cookies[1]

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    refresh_cookie = _get_cookie_from_response(response, 'refresh_foo')
    refresh_csrf_cookie = _get_cookie_from_response(response, 'refresh_foo_csrf')
    assert 'refresh_foo' in refresh_cookie
    assert 'refresh_foo_csrf' in refresh_csrf_cookie

    # The parse cookie library ignores 'Path' cookies, and we don't know which
    # cookie in the list is the csrf cookie and which is the jwt cookie. So
    # we have to resort to doing string comparisons on both of them.
    assert 'Path=/refresh_protected' in cookies[0]
    assert 'Path=/refresh_protected' in cookies[1]


def test_csrf_token_not_in_cookie(app):
    test_client = app.test_client()

    app.config['JWT_CSRF_IN_COOKIES'] = False

    # Test the default access cookies
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    assert 'access_token_cookie' in access_cookie

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    assert 'refresh_token_cookie' in refresh_cookie


def test_cookies_without_csrf(app):
    test_client = app.test_client()

    app.config['JWT_COOKIE_CSRF_PROTECT'] = False

    # Test the default access cookies
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    assert 'access_token_cookie' in access_cookie

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    assert 'refresh_token_cookie' in refresh_cookie

# TODO test csrf with multi methods
# TODO test headers
# TODO test cookies and headers together
