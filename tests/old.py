import pytest
from datetime import timedelta
from flask import Flask, jsonify, json
from werkzeug.http import parse_cookie

from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, jwt_required,
    jwt_refresh_token_required, fresh_jwt_required, jwt_optional,
    get_current_user, set_access_cookies,
    set_refresh_cookies
)

RSA_PRIVATE = """
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDN+p9a9oMyqRzkae8yLdJcEK0O0WesH6JiMz+KDrpUwAoAM/KP
DnxFnROJDSBHyHEmPVn5x8GqV5lQ9+6l97jdEEcPo6wkshycM82fgcxOmvtAy4Uo
xq/AeplYqplhcUTGVuo4ZldOLmN8ksGmzhWpsOdT0bkYipHCn5sWZxd21QIDAQAB
AoGBAMJ0++KVXXEDZMpjFDWsOq898xNNMHG3/8ZzmWXN161RC1/7qt/RjhLuYtX9
NV9vZRrzyrDcHAKj5pMhLgUzpColKzvdG2vKCldUs2b0c8HEGmjsmpmgoI1Tdf9D
G1QK+q9pKHlbj/MLr4vZPX6xEwAFeqRKlzL30JPD+O6mOXs1AkEA8UDzfadH1Y+H
bcNN2COvCqzqJMwLNRMXHDmUsjHfR2gtzk6D5dDyEaL+O4FLiQCaNXGWWoDTy/HJ
Clh1Z0+KYwJBANqRtJ+RvdgHMq0Yd45MMyy0ODGr1B3PoRbUK8EdXpyUNMi1g3iJ
tXMbLywNkTfcEXZTlbbkVYwrEl6P2N1r42cCQQDb9UQLBEFSTRJE2RRYQ/CL4yt3
cTGmqkkfyr/v19ii2jEpMBzBo8eQnPL+fdvIhWwT3gQfb+WqxD9v10bzcmnRAkEA
mzTgeHd7wg3KdJRtQYTmyhXn2Y3VAJ5SG+3qbCW466NqoCQVCeFwEh75rmSr/Giv
lcDhDZCzFuf3EWNAcmuMfQJARsWfM6q7v2p6vkYLLJ7+VvIwookkr6wymF5Zgb9d
E6oTM2EeUPSyyrj5IdsU2JCNBH1m3JnUflz8p8/NYCoOZg==
-----END RSA PRIVATE KEY-----
"""

RSA_PUBLIC = """
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM36n1r2gzKpHORp7zIt0lwQrQ7RZ6wfomIzP4oOulTACgAz8o8OfEWd
E4kNIEfIcSY9WfnHwapXmVD37qX3uN0QRw+jrCSyHJwzzZ+BzE6a+0DLhSjGr8B6
mViqmWFxRMZW6jhmV04uY3ySwabOFamw51PRuRiKkcKfmxZnF3bVAgMBAAE=
-----END RSA PUBLIC KEY-----
"""


def cartesian_product_general_configs():
    jwt_identity_claims = ['identity', 'sub']

    configs = []
    for identity in jwt_identity_claims:
        configs.append({
            'JWT_SECRET_KEY': 'testing_secret_key',
            'JWT_ALGORITHM': 'HS256',
            'JWT_IDENTITY_CLAIM': identity
        })
        configs.append({
            'JWT_PUBLIC_KEY': RSA_PUBLIC,
            'JWT_PRIVATE_KEY': RSA_PRIVATE,
            'JWT_ALGORITHM': 'RS256',
            'JWT_IDENTITY_CLAIM': identity
        })
    return configs


def cartesian_product_header_configs():
    token_locations = ['headers', ['cookies', 'headers']]
    header_names = ['Authorization', 'Foo']
    header_types = ['Bearer', 'JWT', '']

    configs = []
    for location in token_locations:
        for header_name in header_names:
            for header_type in header_types:
                config_combination = {
                    'JWT_TOKEN_LOCATION': location,
                    'JWT_HEADER_NAME': header_name,
                    'JWT_HEADER_TYPE': header_type
                }
                configs.append(config_combination)
    return configs


def cartesian_product_cookie_configs():
    token_locations = [['cookies'], ['cookies', 'headers']]
    access_cookie_names = ['access_token_cookie', 'access_foo']
    refresh_cookie_names = ['refresh_token_cookie', 'refresh_foo']

    configs = []
    for location in token_locations:
        for access_name in access_cookie_names:
            for refresh_name in refresh_cookie_names:
                config_combination = {
                    'JWT_TOKEN_LOCATION': location,
                    'JWT_ACCESS_COOKIE_NAME': access_name,
                    'JWT_REFRESH_COOKIE_NAME': refresh_name
                }
                configs.append(config_combination)
    return configs


COOKIE_COMBINATIONS = cartesian_product_cookie_configs()
HEADER_COMBINATIONS = cartesian_product_header_configs()
CONFIG_COMBINATIONS = cartesian_product_general_configs()


@pytest.fixture(scope='function', params=CONFIG_COMBINATIONS)
def app(request):
    app = Flask(__name__)

    for key, value in request.param.items():
        app.config[key] = value

    JWTManager(app)

    @app.route('/fresh_access_jwt', methods=['POST'])
    def fresh_access_jwt():
        access_token = create_access_token('username', fresh=True)
        return jsonify(jwt=access_token)

    @app.route('/cookie_fresh_access_jwt', methods=['POST'])
    def cookie_fresh_access_jwt():
        access_token = create_access_token('username', fresh=True)
        resp = jsonify(success=True)
        set_access_cookies(resp, access_token)
        return resp

    @app.route('/not_fresh_access_jwt', methods=['POST'])
    def not_fresh_access_jwt():
        access_token = create_access_token('username', fresh=False)
        return jsonify(jwt=access_token)

    @app.route('/cookie_not_fresh_access_jwt', methods=['POST'])
    def cookie_not_fresh_access_jwt():
        access_token = create_access_token('username', fresh=False)
        resp = jsonify(success=True)
        set_access_cookies(resp, access_token)
        return resp

    @app.route('/custom_expires_access_jwt', methods=['POST'])
    def custom_expires_access():
        expires = timedelta(minutes=5)
        access_token = create_access_token('username', expires_delta=expires)
        return jsonify(jwt=access_token)

    @app.route('/refresh_jwt', methods=['POST'])
    def refresh_jwt():
        refresh_token = create_refresh_token('username')
        return jsonify(jwt=refresh_token)

    @app.route('/cookie_refresh_jwt', methods=['POST'])
    def cookie_refresh_jwt():
        refresh_token = create_refresh_token('username')
        resp = jsonify(success=True)
        set_refresh_cookies(resp, refresh_token)
        return resp

    @app.route('/custom_expires_refresh_jwt', methods=['POST'])
    def custom_expires_refresh_jwt():
        expires = timedelta(minutes=5)
        refresh_token = create_refresh_token('username', expires_delta=expires)
        return jsonify(jwt=refresh_token)

    @app.route('/protected', methods=['GET', 'POST'])
    @jwt_required
    def protected():
        return jsonify(foo='bar')

    @app.route('/fresh_protected', methods=['GET', 'POST'])
    @fresh_jwt_required
    def fresh_protected():
        return jsonify(foo='bar')

    @app.route('/refresh_protected', methods=['GET', 'POST'])
    @jwt_refresh_token_required
    def refresh_protected():
        return jsonify(foo='bar')

    @app.route('/optional_protected', methods=['GET', 'POST'])
    @jwt_optional
    def optional_protected():
        if get_current_user():
            return jsonify(foo='baz')
        else:
            return jsonify(foo='bar')

    @app.route('/not_protected', methods=['GET', 'POST'])
    def not_protected():
        return jsonify(foo='bar')

    return app


@pytest.fixture(scope='function', params=HEADER_COMBINATIONS)
def headers_app(request, app):
    for key, value in request.param.items():
        app.config[key] = value
    return app


@pytest.fixture(scope='function', params=COOKIE_COMBINATIONS)
def cookies_app(request, app):
    for key, value in request.param.items():
        app.config[key] = value
    return app


def get_fresh_jwt(test_client):
    response = test_client.post('/fresh_access_jwt')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert 'jwt' in json_data
    return json_data['jwt']


def get_non_fresh_jwt(test_client):
    response = test_client.post('/not_fresh_access_jwt')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert 'jwt' in json_data
    return json_data['jwt']


def get_refresh_jwt(test_client):
    response = test_client.post('/refresh_jwt')
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert 'jwt' in json_data
    return json_data['jwt']


def _get_jwt_from_response_cookie(response, cookie_name):
    cookies = response.headers.getlist('Set-Cookie')
    for cookie in cookies:
        parsed_cookie = parse_cookie(cookie)
        for c_key, c_val in parsed_cookie.items():
            if c_key == cookie_name:
                return c_val
    raise Exception('jwt cooke value not found')


def get_cookie_fresh_jwt(test_client):
    response = test_client.post('/cookie_fresh_access_jwt')
    assert response.status_code == 200

    app = test_client.application
    access_cookie_name = app.config['JWT_ACCESS_COOKIE_NAME']
    return _get_jwt_from_response_cookie(response, access_cookie_name)


def get_cookie_non_fresh_jwt(test_client):
    response = test_client.post('/cookie_not_fresh_access_jwt')
    assert response.status_code == 200

    app = test_client.application
    access_cookie_name = app.config['JWT_ACCESS_COOKIE_NAME']
    return _get_jwt_from_response_cookie(response, access_cookie_name)


def get_cookie_refresh_jwt(test_client):
    response = test_client.post('/cookie_refresh_jwt')
    assert response.status_code == 200

    app = test_client.application
    access_cookie_name = app.config['JWT_REFRESH_COOKIE_NAME']
    return _get_jwt_from_response_cookie(response, access_cookie_name)


def make_request(test_client, request_type, request_url, headers=None, cookies=None):
    if cookies is None:
        cookies = {}
    if cookies:
        for c_key, c_val in cookies.items():
            test_client.set_cookie('/', c_key, c_val)

    request_type = getattr(test_client, request_type.lower())
    return request_type(
        request_url,
        content_type='application/json',
        headers=headers
    )


def make_jwt_headers_request(test_client, jwt, request_type, request_url):
    app = test_client.application
    header_name = app.config['JWT_HEADER_NAME']
    header_type = app.config['JWT_HEADER_TYPE']
    headers = {header_name: '{} {}'.format(header_type, jwt).strip()}
    return make_request(test_client, request_type, request_url, headers=headers)


def make_jwt_cookies_request(test_client, jwt, request_type, request_url):
    app = test_client.application
    cookie_name = app.config['JWT_ACCESS_COOKIE_NAME']
    cookies = {cookie_name: jwt}
    return make_request(test_client, request_type, request_url, cookies=cookies)


@pytest.mark.parametrize("fail_endpoint", [
    '/protected',
    '/fresh_protected',
    '/refresh_protected',
])
@pytest.mark.parametrize('token_location', ['headers', 'cookies', ['cookies', 'headers']])
def test_blocked_endpoints_without_jwt(app, fail_endpoint, token_location):
    app.config['JWT_TOKEN_LOCATION'] = token_location
    test_client = app.test_client()
    response = make_request(test_client, 'GET', fail_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    expected_errors = (
        {'msg': 'Missing Authorization Header'},
        {'msg': 'Missing cookie "access_token_cookie"'},
        {'msg': 'Missing cookie "refresh_token_cookie"'},
        {'msg': 'Missing JWT in headers and cookies'},
    )
    assert json_data in expected_errors
    assert response.status_code == 401


@pytest.mark.parametrize("success_endpoint", [
    '/optional_protected',
    '/not_protected',
])
@pytest.mark.parametrize('token_location', ['headers', 'cookies', ['cookies', 'headers']])
def test_accessable_endpoints_without_jwt(app, success_endpoint, token_location):
    app.config['JWT_TOKEN_LOCATION'] = token_location
    test_client = app.test_client()
    response = make_request(test_client, 'GET', success_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("success_endpoint", [
    '/protected',
    '/fresh_protected',
    '/optional_protected',
    '/not_protected',
])
def test_accessable_endpoints_with_fresh_jwt_in_headers(headers_app, success_endpoint):
    test_client = headers_app.test_client()
    fresh_jwt = get_fresh_jwt(test_client)
    response = make_jwt_headers_request(test_client, fresh_jwt, 'GET', success_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("failure_endpoint", ['/refresh_protected'])
def test_blocked_endpoints_with_fresh_jwt_in_headers(headers_app, failure_endpoint):
    test_client = headers_app.test_client()
    fresh_jwt = get_fresh_jwt(test_client)
    response = make_jwt_headers_request(test_client, fresh_jwt, 'GET', failure_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'msg': 'Only refresh tokens can access this endpoint'}
    assert response.status_code == 422


@pytest.mark.parametrize("success_endpoint", [
    '/protected',
    '/optional_protected',
    '/not_protected',
])
def test_accessable_endpoints_with_non_fresh_jwt_in_headers(headers_app, success_endpoint):
    test_client = headers_app.test_client()
    jwt = get_non_fresh_jwt(test_client)
    response = make_jwt_headers_request(test_client, jwt, 'GET', success_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("failure_endpoint", [
    '/refresh_protected',
    '/fresh_protected'
])
def test_blocked_endpoints_with_non_fresh_jwt_in_headers(headers_app, failure_endpoint):
    test_client = headers_app.test_client()
    jwt = get_non_fresh_jwt(test_client)
    response = make_jwt_headers_request(test_client, jwt, 'GET', failure_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    expected_errors = (
        (422, {'msg': 'Only refresh tokens can access this endpoint'}),
        (401, {'msg': 'Fresh token required'})
    )
    assert (response.status_code, json_data) in expected_errors


@pytest.mark.parametrize("success_endpoint", [
    '/refresh_protected',
    '/not_protected'
])
def test_accessable_endpoints_with_refresh_jwt_in_headers(headers_app, success_endpoint):
    test_client = headers_app.test_client()
    jwt = get_refresh_jwt(test_client)
    response = make_jwt_headers_request(test_client, jwt, 'GET', success_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("failure_endpoint", [
    '/fresh_protected',
    '/protected',
    '/optional_protected'
])
def test_blocked_endpoints_with_refresh_jwt_in_headers(headers_app, failure_endpoint):
    test_client = headers_app.test_client()
    jwt = get_refresh_jwt(test_client)
    response = make_jwt_headers_request(test_client, jwt, 'GET', failure_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'msg': 'Only access tokens can access this endpoint'}
    assert response.status_code == 422


@pytest.mark.parametrize("token_location", ['headers', ['cookies', 'headers']])
def test_bad_header_name_blocks_protected_endpoints(app, token_location):
    app.config['JWT_TOKEN_LOCATION'] = token_location
    app.config['JWT_HEADER_NAME'] = 'Foo'

    test_client = app.test_client()
    jwt = get_fresh_jwt(test_client)

    headers = {'Authorization': 'Bearer {}'.format(jwt)}
    response = make_request(test_client, 'GET', '/protected', headers=headers)
    json_data = json.loads(response.get_data(as_text=True))

    expected_json = (
        {'msg': 'Missing Foo Header'},
        {'msg': 'Missing JWT in headers and cookies'}
    )
    assert json_data in expected_json
    assert response.status_code == 401


@pytest.mark.parametrize("token_location", ['headers', ['cookies', 'headers']])
@pytest.mark.parametrize("header_type", ['Foo', ''])
def test_bad_header_type_blocks_protected_endpoints(app, token_location, header_type):
    app.config['JWT_TOKEN_LOCATION'] = token_location
    app.config['JWT_HEADER_TYPE'] = header_type

    test_client = app.test_client()
    jwt = get_fresh_jwt(test_client)

    headers = {'Authorization': 'Bearer {}'.format(jwt)}
    response = make_request(test_client, 'GET', '/protected', headers=headers)
    json_data = json.loads(response.get_data(as_text=True))

    expected_json = (
        {'msg': "Bad Authorization header. Expected value '<JWT>'"},
        {'msg': "Bad Authorization header. Expected value 'Foo <JWT>'"}
    )

    assert json_data in expected_json
    assert response.status_code == 422


@pytest.mark.parametrize("success_endpoint", [
    '/protected',
    '/fresh_protected',
    '/optional_protected',
    '/not_protected',
])
def test_accessable_endpoints_with_fresh_jwt_in_cookies(cookies_app, success_endpoint):
    test_client = cookies_app.test_client()
    fresh_jwt = get_cookie_fresh_jwt(test_client)
    response = make_jwt_cookies_request(test_client, fresh_jwt, 'GET', success_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'foo': 'bar'}
    assert response.status_code == 200


# TODO when using cookies, actually send the wrong cookie type (refresh/access)
#      into the header that expects the other type. The cookies have different
#      names, so this test doesn't actually test that case
@pytest.mark.parametrize("failure_endpoint", ['/refresh_protected'])
def test_blocked_endpoints_with_fresh_jwt_in_headers(cookies_app, failure_endpoint):
    test_client = cookies_app.test_client()
    fresh_jwt = get_cookie_fresh_jwt(test_client)
    response = make_jwt_cookies_request(test_client, fresh_jwt, 'GET', failure_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    expected_errors = (
       {'msg': 'Missing cookie "{}"'.format(cookies_app.config['JWT_REFRESH_COOKIE_NAME'])},
       {'msg': 'Missing JWT in headers and cookies'}
    )
    assert json_data in expected_errors
    assert response.status_code == 401


@pytest.mark.parametrize("success_endpoint", [
    '/protected',
    '/optional_protected',
    '/not_protected',
])
def test_accessable_endpoints_with_non_fresh_jwt_in_cookies(cookies_app, success_endpoint):
    test_client = cookies_app.test_client()
    fresh_jwt = get_cookie_non_fresh_jwt(test_client)
    response = make_jwt_cookies_request(test_client, fresh_jwt, 'GET', success_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("failure_endpoint", [
    '/refresh_protected',
    '/fresh_protected'
])
def test_blocked_endpoints_with_non_fresh_jwt_in_cookies(cookies_app, failure_endpoint):
    test_client = cookies_app.test_client()
    fresh_jwt = get_cookie_non_fresh_jwt(test_client)
    response = make_jwt_cookies_request(test_client, fresh_jwt, 'GET', failure_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    refresh_cookie_name = cookies_app.config['JWT_REFRESH_COOKIE_NAME']
    expected_errors = (
        {'msg': 'Missing cookie "{}"'.format(refresh_cookie_name)},
        {'msg': 'Missing JWT in headers and cookies'},
        {'msg': 'Fresh token required'}
    )
    assert json_data in expected_errors
    assert response.status_code == 401


@pytest.mark.parametrize("success_endpoint", [
    '/refresh_protected',
    '/not_protected'
])
def test_accessable_endpoints_with_refresh_jwt_in_cookies(cookies_app, success_endpoint):
    test_client = cookies_app.test_client()
    refresh_jwt = get_cookie_refresh_jwt(test_client)
    response = make_jwt_cookies_request(test_client, refresh_jwt, 'GET', success_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    assert json_data == {'foo': 'bar'}
    assert response.status_code == 200


@pytest.mark.parametrize("failure_endpoint", [
    '/fresh_protected',
    '/protected',
    '/optional_protected'
])
def test_blocked_endpoints_with_refresh_jwt_in_cookies(cookies_app, failure_endpoint):
    test_client = cookies_app.test_client()
    refresh_jwt = get_cookie_refresh_jwt(test_client)
    response = make_jwt_cookies_request(test_client, refresh_jwt, 'GET', failure_endpoint)
    json_data = json.loads(response.get_data(as_text=True))

    # TODO is this right? I would expect an error about missing the cookie. I
    #      think this is broke as we are only sending in the access cookie
    #      not the refresh cookie when doing make_jwt_cookies_request
    expected_errors = (
        {'msg': 'Only access tokens can access this endpoint'},
    )
    assert json_data in expected_errors
    assert response.status_code == 422


# TODO test sending in headers when cookie_locations and vice versa
# TODO when using cookies with csrf, test GET and POST requests
# TODO test that verifies the jwt identity claim actually changes (sub/identity)
# TODO test possible combinations for jwt_optional
# TODO simple test that the other cookie overrides are working
# TODO test having the access and refresh cookie be the same name?


# Various options we want to test stuff here (with different expectations for
# success or failure)
#   - JWT in cookies and pass in with cookies
#   - JWT in cookies and pass in with headers
#   - JWT in headers and pass in with cookies
#   - JWT in headers and pass in with headers
#   - JWT in headers and cookies and pass in with cookies
#   - JWT in headers and cookies and pass in with headers
#
# Everything we want to actually test with the above configurations:
#   - all protected endpoints with expected jwts
#   - all protected endpoints with unexpected jwts
#   - all protected endpoints with expired jwts
#   - all protected endpoints with tampered with jwts
#   - all protected endpoints with tampered with no jwts
#   - all protected endpoints with tampered with no revoked jts
#   - all protected endpoints with tampered with no user loader from jwts
#   - all protected endpoints with tampered with no no user loader from jwts
#   - all protected endpoints with tampered with verified claims in jwts
#   - all protected endpoints with tampered with failed verified claims in jwts
