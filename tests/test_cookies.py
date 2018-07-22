import pytest
from flask import Flask, jsonify

from flask_jwt_extended import (
    jwt_required, JWTManager, jwt_refresh_token_required, create_access_token,
    create_refresh_token, set_access_cookies, set_refresh_cookies,
    unset_jwt_cookies, unset_access_cookies, unset_refresh_cookies, jwt_optional
)


def _get_cookie_from_response(response, cookie_name):
    cookie_headers = response.headers.getlist('Set-Cookie')
    for header in cookie_headers:
        attributes = header.split(';')
        if cookie_name in attributes[0]:
            cookie = {}
            for attr in attributes:
                split = attr.split('=')
                cookie[split[0].strip().lower()] = split[1] if len(split) > 1 else True
            return cookie
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

    @app.route('/delete_access_tokens', methods=['GET'])
    def delete_access_tokens():
        resp = jsonify(access_revoked=True)
        unset_access_cookies(resp)
        return resp

    @app.route('/delete_refresh_tokens', methods=['GET'])
    def delete_refresh_tokens():
        resp = jsonify(refresh_revoked=True)
        unset_refresh_cookies(resp)
        return resp

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def protected():
        return jsonify(foo='bar')

    @app.route('/post_protected', methods=['POST'])
    @jwt_required
    def post_protected():
        return jsonify(foo='bar')

    @app.route('/refresh_protected', methods=['GET'])
    @jwt_refresh_token_required
    def refresh_protected():
        return jsonify(foo='bar')

    @app.route('/post_refresh_protected', methods=['POST'])
    @jwt_refresh_token_required
    def post_refresh_protected():
        return jsonify(foo='bar')

    @app.route('/optional_post_protected', methods=['POST'])
    @jwt_optional
    def optional_post_protected():
        return jsonify(foo='bar')

    return app


@pytest.mark.parametrize("options", [
    ('/refresh_token', 'refresh_token_cookie', '/refresh_protected', '/delete_refresh_tokens'),  # nopep8
    ('/access_token', 'access_token_cookie', '/protected', '/delete_access_tokens')
])
def test_jwt_refresh_required_with_cookies(app, options):
    test_client = app.test_client()
    auth_url, cookie_name, protected_url, delete_url = options

    # Test without cookies
    response = test_client.get(protected_url)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing cookie "{}"'.format(cookie_name)}

    # Test after receiving cookies
    test_client.get(auth_url)
    response = test_client.get(protected_url)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    # Test after issuing a 'logout' to delete the cookies
    test_client.get(delete_url)
    response = test_client.get(protected_url)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing cookie "{}"'.format(cookie_name)}

    # log back in once more to test that clearing all tokens works
    test_client.get(auth_url)
    response = test_client.get(protected_url)
    assert response.status_code == 200

    test_client.get("/delete_tokens")
    response = test_client.get(protected_url)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing cookie "{}"'.format(cookie_name)}


@pytest.mark.parametrize("options", [
    ('/refresh_token', 'csrf_refresh_token', '/post_refresh_protected'),
    ('/access_token', 'csrf_access_token', '/post_protected')
])
def test_default_access_csrf_protection(app, options):
    test_client = app.test_client()
    auth_url, csrf_cookie_name, post_url = options

    # Get the jwt cookies and csrf double submit tokens
    response = test_client.get(auth_url)
    csrf_token = _get_cookie_from_response(response, csrf_cookie_name)[csrf_cookie_name]

    # Test you cannot post without the additional csrf protection
    response = test_client.post(post_url)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing CSRF token in headers'}

    # Test that you can post with the csrf double submit value
    csrf_headers = {'X-CSRF-TOKEN': csrf_token}
    response = test_client.post(post_url, headers=csrf_headers)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}


@pytest.mark.parametrize("options", [
    ('/refresh_token', '/post_refresh_protected'),
    ('/access_token', '/post_protected')
])
def test_non_matching_csrf_token(app, options):
    test_client = app.test_client()
    auth_url, post_url = options

    # Get the jwt cookies and csrf double submit tokens
    test_client.get(auth_url)
    csrf_headers = {'X-CSRF-TOKEN': 'totally_wrong_token'}
    response = test_client.post(post_url, headers=csrf_headers)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'CSRF double submit tokens do not match'}


@pytest.mark.parametrize("options", [
    ('/refresh_token', '/post_refresh_protected'),
    ('/access_token', '/post_protected')
])
def test_csrf_disabled(app, options):
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    test_client = app.test_client()
    auth_url, post_url = options

    # Get the jwt cookies and csrf double submit tokens
    test_client.get(auth_url)
    response = test_client.post(post_url)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}


@pytest.mark.parametrize("options", [
    ('/refresh_token', 'csrf_refresh_token', '/post_refresh_protected'),
    ('/access_token', 'csrf_access_token', '/post_protected')
])
def test_csrf_with_custom_header_names(app, options):
    app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = 'FOO'
    app.config['JWT_REFRESH_CSRF_HEADER_NAME'] = 'FOO'
    test_client = app.test_client()
    auth_url, csrf_cookie_name, post_url = options

    # Get the jwt cookies and csrf double submit tokens
    response = test_client.get(auth_url)
    csrf_token = _get_cookie_from_response(response, csrf_cookie_name)[csrf_cookie_name]

    # Test that you can post with the csrf double submit value
    csrf_headers = {'FOO': csrf_token}
    response = test_client.post(post_url, headers=csrf_headers)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}


@pytest.mark.parametrize("options", [
    ('/refresh_token', 'csrf_refresh_token', '/refresh_protected', '/post_refresh_protected'),  # nopep8
    ('/access_token', 'csrf_access_token', '/protected', '/post_protected')
])
def test_custom_csrf_methods(app, options):
    app.config['JWT_CSRF_METHODS'] = ['GET']
    test_client = app.test_client()
    auth_url, csrf_cookie_name, get_url, post_url = options

    # Get the jwt cookies and csrf double submit tokens
    response = test_client.get(auth_url)
    csrf_token = _get_cookie_from_response(response, csrf_cookie_name)[csrf_cookie_name]

    # Insure we can now do posts without csrf
    response = test_client.post(post_url)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    # Insure GET requests now fail without csrf
    response = test_client.get(get_url)
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing CSRF token in headers'}

    # Insure GET requests now succeed with csrf
    csrf_headers = {'X-CSRF-TOKEN': csrf_token}
    response = test_client.get(get_url, headers=csrf_headers)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}


def test_setting_cookies_wihout_cookies_enabled(app):
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    test_client = app.test_client()

    response = test_client.get('/access_token')
    assert response.status_code == 500
    response = test_client.get('/refresh_token')
    assert response.status_code == 500
    response = test_client.get('/delete_tokens')
    assert response.status_code == 500
    response = test_client.get('/delete_access_tokens')
    assert response.status_code == 500
    response = test_client.get('/delete_refresh_tokens')
    assert response.status_code == 500


def test_default_cookie_options(app):
    test_client = app.test_client()

    # Test the default access cookies
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    assert access_cookie is not None
    assert access_cookie['path'] == '/'
    assert access_cookie['httponly'] is True
    assert 'samesite' not in access_cookie

    access_csrf_cookie = _get_cookie_from_response(response, 'csrf_access_token')
    assert access_csrf_cookie is not None
    assert access_csrf_cookie['path'] == '/'
    assert 'httponly' not in access_csrf_cookie
    assert 'samesite' not in access_csrf_cookie

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    assert refresh_cookie is not None
    assert refresh_cookie['path'] == '/'
    assert refresh_cookie['httponly'] is True
    assert 'samesite' not in refresh_cookie

    refresh_csrf_cookie = _get_cookie_from_response(response, 'csrf_refresh_token')
    assert refresh_csrf_cookie is not None
    assert refresh_csrf_cookie['path'] == '/'
    assert 'httponly' not in refresh_csrf_cookie
    assert 'samesite' not in refresh_csrf_cookie


def test_custom_cookie_options(app):
    test_client = app.test_client()

    app.config['JWT_COOKIE_SECURE'] = True
    app.config['JWT_COOKIE_DOMAIN'] = 'test.com'
    app.config['JWT_SESSION_COOKIE'] = False
    app.config['JWT_COOKIE_SAMESITE'] = 'Strict'

    # Test access cookies with changed options
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    assert access_cookie is not None
    assert access_cookie['domain'] == 'test.com'
    assert access_cookie['path'] == '/'
    assert access_cookie['expires'] != ''
    assert access_cookie['httponly'] is True
    assert access_cookie['secure'] is True
    assert access_cookie['samesite'] == 'Strict'

    access_csrf_cookie = _get_cookie_from_response(response, 'csrf_access_token')
    assert access_csrf_cookie is not None
    assert access_csrf_cookie['path'] == '/'
    assert access_csrf_cookie['secure'] is True
    assert access_csrf_cookie['domain'] == 'test.com'
    assert access_csrf_cookie['expires'] != ''
    assert access_csrf_cookie['samesite'] == 'Strict'

    # Test refresh cookies with changed options
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    assert refresh_cookie is not None
    assert refresh_cookie['domain'] == 'test.com'
    assert refresh_cookie['path'] == '/'
    assert refresh_cookie['httponly'] is True
    assert refresh_cookie['secure'] is True
    assert refresh_cookie['expires'] != ''
    assert refresh_cookie['samesite'] == 'Strict'

    refresh_csrf_cookie = _get_cookie_from_response(response, 'csrf_refresh_token')
    assert refresh_csrf_cookie is not None
    assert refresh_csrf_cookie['path'] == '/'
    assert refresh_csrf_cookie['secure'] is True
    assert refresh_csrf_cookie['domain'] == 'test.com'
    assert refresh_csrf_cookie['expires'] != ''
    assert refresh_csrf_cookie['samesite'] == 'Strict'


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
    assert access_cookie is not None
    assert access_csrf_cookie is not None
    assert access_cookie['path'] == '/protected'
    assert access_csrf_cookie['path'] == '/protected'

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 2  # JWT and CSRF value

    refresh_cookie = _get_cookie_from_response(response, 'refresh_foo')
    refresh_csrf_cookie = _get_cookie_from_response(response, 'refresh_foo_csrf')
    assert refresh_cookie is not None
    assert refresh_csrf_cookie is not None
    assert refresh_cookie['path'] == '/refresh_protected'
    assert refresh_csrf_cookie['path'] == '/refresh_protected'


def test_csrf_token_not_in_cookie(app):
    test_client = app.test_client()

    app.config['JWT_CSRF_IN_COOKIES'] = False

    # Test the default access cookies
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    assert access_cookie is not None

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    assert refresh_cookie is not None


def test_cookies_without_csrf(app):
    test_client = app.test_client()

    app.config['JWT_COOKIE_CSRF_PROTECT'] = False

    # Test the default access cookies
    response = test_client.get('/access_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    access_cookie = _get_cookie_from_response(response, 'access_token_cookie')
    assert access_cookie is not None

    # Test the default refresh cookies
    response = test_client.get('/refresh_token')
    cookies = response.headers.getlist('Set-Cookie')
    assert len(cookies) == 1
    refresh_cookie = _get_cookie_from_response(response, 'refresh_token_cookie')
    assert refresh_cookie is not None


def test_jwt_optional_with_csrf_enabled(app):
    test_client = app.test_client()

    # User without a token should be able to reach the endpoint without
    # getting a CSRF error
    response = test_client.post('/optional_post_protected')
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}

    # User with a token should still get a CSRF error if csrf not present
    response = test_client.get('/access_token')
    csrf_cookie = _get_cookie_from_response(response, 'csrf_access_token')
    csrf_token = csrf_cookie['csrf_access_token']
    response = test_client.post('/optional_post_protected')
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Missing CSRF token in headers'}
