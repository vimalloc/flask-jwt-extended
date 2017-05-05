import json
import time
import unittest
from datetime import datetime, timedelta

from flask import Flask, jsonify
import jwt

from flask_jwt_extended.tokens import encode_access_token
from flask_jwt_extended.utils import get_jwt_claims, \
    get_jwt_identity, set_refresh_cookies, set_access_cookies, unset_jwt_cookies
from flask_jwt_extended import JWTManager, create_refresh_token, \
    jwt_refresh_token_required, create_access_token, fresh_jwt_required, \
    jwt_required, get_raw_jwt


class TestEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.app.config['JWT_ALGORITHM'] = 'HS256'
        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=1)
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=1)
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            ret = {
                'access_token': create_access_token('test', fresh=True),
                'refresh_token': create_refresh_token('test')
            }
            return jsonify(ret), 200

        @self.app.route('/auth/refresh', methods=['POST'])
        @jwt_refresh_token_required
        def refresh():
            username = get_jwt_identity()
            ret = {'access_token': create_access_token(username, fresh=False)}
            return jsonify(ret), 200

        @self.app.route('/auth/fresh-login', methods=['POST'])
        def fresh_login():
            ret = {'access_token': create_access_token('test', fresh=True)}
            return jsonify(ret), 200

        @self.app.route('/protected')
        @jwt_required
        def protected():
            return jsonify({'msg': "hello world"})

        @self.app.route('/fresh-protected')
        @fresh_jwt_required
        def fresh_protected():
            return jsonify({'msg': "fresh hello world"})

    def _jwt_post(self, url, jwt):
        response = self.client.post(url, content_type='application/json',
                                    headers={'Authorization': 'Bearer {}'.format(jwt)})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def _jwt_get(self, url, jwt, header_name='Authorization', header_type='Bearer'):
        header_type = '{} {}'.format(header_type, jwt).strip()
        response = self.client.get(url, headers={header_name: header_type})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def test_login(self):
        response = self.client.post('/auth/login')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)

    def test_fresh_login(self):
        response = self.client.post('/auth/fresh-login')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertNotIn('refresh_token', data)

    def test_refresh(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']
        refresh_token = data['refresh_token']

        status_code, data = self._jwt_post('/auth/refresh', refresh_token)
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertNotIn('refresh_token', data)

    def test_wrong_token_refresh(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        # Try to refresh with an access token instead of a refresh one
        status_code, data = self._jwt_post('/auth/refresh', access_token)
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

    def test_jwt_required(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        fresh_access_token = data['access_token']
        refresh_token = data['refresh_token']

        # Test it works with a fresh token
        status, data = self._jwt_get('/protected', fresh_access_token)
        self.assertEqual(data, {'msg': 'hello world'})
        self.assertEqual(status, 200)

        # Test it works with a non-fresh access token
        _, data = self._jwt_post('/auth/refresh', refresh_token)
        non_fresh_token = data['access_token']
        status, data = self._jwt_get('/protected', non_fresh_token)
        self.assertEqual(status, 200)
        self.assertEqual(data, {'msg': 'hello world'})

    def test_jwt_required_wrong_token(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        refresh_token = data['refresh_token']

        # Shouldn't work with a refresh token
        status, text = self._jwt_get('/protected', refresh_token)
        self.assertEqual(status, 422)

    def test_fresh_jwt_required(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        fresh_access_token = data['access_token']
        refresh_token = data['refresh_token']

        # Test it works with a fresh token
        status, data = self._jwt_get('/fresh-protected', fresh_access_token)
        self.assertEqual(data, {'msg': 'fresh hello world'})
        self.assertEqual(status, 200)

        # Test it works with a non-fresh access token
        _, data = self._jwt_post('/auth/refresh', refresh_token)
        non_fresh_token = data['access_token']
        status, text = self._jwt_get('/fresh-protected', non_fresh_token)
        self.assertEqual(status, 401)

    def test_fresh_jwt_required_wrong_token(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        refresh_token = data['refresh_token']

        # Shouldn't work with a refresh token
        status, text = self._jwt_get('/fresh-protected', refresh_token)
        self.assertEqual(status, 422)

    def test_without_secret_key(self):
        app = Flask(__name__)
        app.testing = True  # Propagate exceptions
        JWTManager(app)
        client = app.test_client()

        @app.route('/login', methods=['POST'])
        def login():
            ret = {'access_token': create_access_token('test', fresh=True)}
            return jsonify(ret), 200

        with self.assertRaises(RuntimeError):
            client.post('/login')

    def test_bad_jwt_requests(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        # Test with no authorization header
        response = self.client.get('/protected')
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Test with missing type in authorization header
        auth_header = access_token
        response = self.client.get('/protected', headers={'Authorization': auth_header})
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

        # Test with type not being Bearer in authorization header
        auth_header = "BANANA {}".format(access_token)
        response = self.client.get('/protected', headers={'Authorization': auth_header})
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

        # Test with too many items in auth header
        auth_header = "Bearer {} BANANA".format(access_token)
        response = self.client.get('/protected', headers={'Authorization': auth_header})
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

    def test_bad_tokens(self):
        # Test expired access token
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']
        status_code, data = self._jwt_get('/protected', access_token)
        self.assertEqual(status_code, 200)
        self.assertIn('msg', data)
        time.sleep(2)
        status_code, data = self._jwt_get('/protected', access_token)
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Test expired refresh token
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        refresh_token = data['refresh_token']
        status_code, data = self._jwt_post('/auth/refresh', refresh_token)
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertNotIn('msg', data)
        time.sleep(2)
        status_code, data = self._jwt_post('/auth/refresh', refresh_token)
        self.assertEqual(status_code, 401)
        self.assertNotIn('access_token', data)
        self.assertIn('msg', data)

        # Test Bogus token
        auth_header = "Bearer {}".format('this_is_totally_an_access_token')
        response = self.client.get('/protected', headers={'Authorization': auth_header})
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

        # Test token that was signed with a different key
        with self.app.test_request_context():
            token = encode_access_token('foo', 'newsecret', 'HS256',
                                        timedelta(minutes=5), True, {}, csrf=False)
        auth_header = "Bearer {}".format(token)
        response = self.client.get('/protected', headers={'Authorization': auth_header})
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

        # Test with valid token that is missing required claims
        now = datetime.utcnow()
        token_data = {'exp': now + timedelta(minutes=5)}
        encoded_token = jwt.encode(token_data, self.app.config['SECRET_KEY'],
                                   self.app.config['JWT_ALGORITHM']).decode('utf-8')
        auth_header = "Bearer {}".format(encoded_token)
        response = self.client.get('/protected', headers={'Authorization': auth_header})
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

    def test_jwt_identity_claims(self):
        # Setup custom claims
        @self.jwt_manager.user_claims_loader
        def custom_claims(identity):
            return {'foo': 'bar'}

        @self.app.route('/claims')
        @jwt_required
        def claims():
            return jsonify({
                'username': get_jwt_identity(),
                'claims': get_jwt_claims()
            })


        # Login
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        # Test our custom endpoint
        status, data = self._jwt_get('/claims', access_token)
        self.assertEqual(status, 200)
        self.assertEqual(data, {'username': 'test', 'claims': {'foo': 'bar'}})

    def test_jwt_raw_token(self):
        # Endpoints that uses get raw tokens and returns the keys
        @self.app.route('/claims')
        @jwt_required
        def claims():
            jwt = get_raw_jwt()
            claims_keys = [claim for claim in jwt]
            return jsonify(claims_keys), 200

        # Login
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        # Test our custom endpoint
        status, data = self._jwt_get('/claims', access_token)
        self.assertEqual(status, 200)
        self.assertIn('exp', data)
        self.assertIn('iat', data)
        self.assertIn('nbf', data)
        self.assertIn('jti', data)
        self.assertIn('identity', data)
        self.assertIn('fresh', data)
        self.assertIn('type', data)
        self.assertIn('user_claims', data)

    def test_different_headers(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        self.app.config['JWT_HEADER_TYPE'] = 'JWT'
        status, data = self._jwt_get('/protected', access_token, header_type='JWT')
        self.assertEqual(data, {'msg': 'hello world'})
        self.assertEqual(status, 200)

        self.app.config['JWT_HEADER_TYPE'] = ''
        status, data = self._jwt_get('/protected', access_token, header_type='')
        self.assertEqual(data, {'msg': 'hello world'})
        self.assertEqual(status, 200)

        self.app.config['JWT_HEADER_TYPE'] = ''
        status, data = self._jwt_get('/protected', access_token, header_type='Bearer')
        self.assertIn('msg', data)
        self.assertEqual(status, 422)

        self.app.config['JWT_HEADER_TYPE'] = 'Bearer'
        self.app.config['JWT_HEADER_NAME'] = 'Auth'
        status, data = self._jwt_get('/protected', access_token, header_name='Auth',
                                     header_type='Bearer')
        self.assertIn('msg', data)
        self.assertEqual(status, 200)

        status, data = self._jwt_get('/protected', access_token, header_name='Authorization',
                                     header_type='Bearer')
        self.assertIn('msg', data)
        self.assertEqual(status, 401)

    def test_cookie_methods_fail_with_headers_configured(self):
        app = Flask(__name__)
        app.config['JWT_TOKEN_LOCATION'] = ['headers']
        app.secret_key = 'super=secret'
        app.testing = True
        JWTManager(app)
        client = app.test_client()

        @app.route('/login-bad', methods=['POST'])
        def bad_login():
            access_token = create_access_token('test')
            resp = jsonify({'login': True})
            set_access_cookies(resp, access_token)
            return resp, 200

        @app.route('/refresh-bad', methods=['POST'])
        def bad_refresh():
            refresh_token = create_refresh_token('test')
            resp = jsonify({'login': True})
            set_refresh_cookies(resp, refresh_token)
            return resp, 200

        @app.route('/logout-bad', methods=['POST'])
        def bad_logout():
            resp = jsonify({'logout': True})
            unset_jwt_cookies(resp)
            return resp, 200

        with self.assertRaises(RuntimeWarning):
            client.post('/login-bad')
        with self.assertRaises(RuntimeWarning):
            client.post('/refresh-bad')
        with self.assertRaises(RuntimeWarning):
            client.post('/logout-bad')

    def test_jwt_with_different_algorithm(self):
        self.app.config['JWT_ALGORITHM'] = 'HS256'
        self.app.secret_key = 'test_secret'
        access_token = encode_access_token(
            identity='bobdobbs',
            secret='test_secret',
            algorithm='HS512',
            expires_delta=timedelta(minutes=5),
            fresh=True,
            user_claims={},
            csrf=False
        )
        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(status, 422)
        self.assertIn('msg', data)


class TestEndpointsWithCookies(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.app.config['JWT_TOKEN_LOCATION'] = 'cookies'
        self.app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
        self.app.config['JWT_REFRESH_COOKIE_PATH'] = '/auth/refresh'
        self.app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
        self.app.config['JWT_ALGORITHM'] = 'HS256'
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            # Create the tokens we will be sending back to the user
            access_token = create_access_token(identity='test')
            refresh_token = create_refresh_token(identity='test')

            # Set the JWTs and the CSRF double submit protection cookies in this response
            resp = jsonify({'login': True})
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp, 200

        @self.app.route('/auth/logout', methods=['POST'])
        def logout():
            resp = jsonify({'logout': True})
            unset_jwt_cookies(resp)
            return resp, 200

        @self.app.route('/auth/refresh', methods=['POST'])
        @jwt_refresh_token_required
        def refresh():
            username = get_jwt_identity()
            access_token = create_access_token(username, fresh=False)
            resp = jsonify({'refresh': True})
            set_access_cookies(resp, access_token)
            return resp, 200

        @self.app.route('/api/protected', methods=['POST'])
        @jwt_required
        def protected():
            return jsonify({'msg': "hello world"})

    def _login(self):
        resp = self.client.post('/auth/login')
        index = 1

        access_cookie_str = resp.headers[index][1]
        access_cookie_key = access_cookie_str.split('=')[0]
        access_cookie_value = "".join(access_cookie_str.split('=')[1:])
        self.client.set_cookie('localhost', access_cookie_key, access_cookie_value)
        index += 1

        if self.app.config['JWT_COOKIE_CSRF_PROTECT']:
            access_csrf_str = resp.headers[index][1]
            access_csrf_key = access_csrf_str.split('=')[0]
            access_csrf_value = "".join(access_csrf_str.split('=')[1:])
            self.client.set_cookie('localhost', access_csrf_key, access_csrf_value)
            index += 1
            access_csrf = access_csrf_value.split(';')[0]
        else:
            access_csrf = ""

        refresh_cookie_str = resp.headers[index][1]
        refresh_cookie_key = refresh_cookie_str.split('=')[0]
        refresh_cookie_value = "".join(refresh_cookie_str.split('=')[1:])
        self.client.set_cookie('localhost', refresh_cookie_key, refresh_cookie_value)
        index += 1

        if self.app.config['JWT_COOKIE_CSRF_PROTECT']:
            refresh_csrf_str = resp.headers[index][1]
            refresh_csrf_key = refresh_csrf_str.split('=')[0]
            refresh_csrf_value = "".join(refresh_csrf_str.split('=')[1:])
            self.client.set_cookie('localhost', refresh_csrf_key, refresh_csrf_value)
            refresh_csrf = refresh_csrf_value.split(';')[0]
        else:
            refresh_csrf = ""

        return access_csrf, refresh_csrf

    def test_headers(self):
        # Try with default options
        resp = self.client.post('/auth/login')
        access_cookie = resp.headers[1][1]
        access_csrf = resp.headers[2][1]
        refresh_cookie = resp.headers[3][1]
        refresh_csrf = resp.headers[4][1]
        self.assertIn('access_token_cookie', access_cookie)
        self.assertIn('csrf_access_token', access_csrf)
        self.assertIn('Path=/', access_csrf)
        self.assertIn('refresh_token_cookie', refresh_cookie)
        self.assertIn('csrf_refresh_token', refresh_csrf)
        self.assertIn('Path=/', refresh_csrf)

        # Try with overwritten options
        self.app.config['JWT_ACCESS_COOKIE_NAME'] = 'new_access_cookie'
        self.app.config['JWT_REFRESH_COOKIE_NAME'] = 'new_refresh_cookie'
        self.app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'x_csrf_access_token'
        self.app.config['JWT_REFRESH_CSRF_COOKIE_NAME'] = 'x_csrf_refresh_token'
        self.app.config['JWT_ACCESS_COOKIE_PATH'] = None
        self.app.config['JWT_REFRESH_COOKIE_PATH'] = None

        resp = self.client.post('/auth/login')
        access_cookie = resp.headers[1][1]
        access_csrf = resp.headers[2][1]
        refresh_cookie = resp.headers[3][1]
        refresh_csrf = resp.headers[4][1]
        self.assertIn('new_access_cookie', access_cookie)
        self.assertIn('x_csrf_access_token', access_csrf)
        self.assertIn('Path=/', access_csrf)
        self.assertIn('new_refresh_cookie', refresh_cookie)
        self.assertIn('x_csrf_refresh_token', refresh_csrf)
        self.assertIn('Path=/', refresh_csrf)

        # Try logout headers
        resp = self.client.post('/auth/logout')
        refresh_cookie = resp.headers[1][1]
        access_cookie = resp.headers[2][1]
        self.assertIn('Expires=Thu, 01-Jan-1970', refresh_cookie)
        self.assertIn('Expires=Thu, 01-Jan-1970', access_cookie)

    def test_endpoints_with_cookies(self):
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = False

        # Try access without logging in
        response = self.client.post('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Try refresh without logging in
        response = self.client.post('/auth/refresh')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Try with logging in
        self._login()
        response = self.client.post('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'msg': 'hello world'})

        # Try refresh without logging in
        response = self.client.post('/auth/refresh')
        access_cookie_str = response.headers[1][1]
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertIn('access_token_cookie', access_cookie_str)
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'refresh': True})

        # Try accessing endpoint with newly refreshed token
        access_cookie_key = access_cookie_str.split('=')[0]
        access_cookie_value = "".join(access_cookie_str.split('=')[1:])
        self.client.set_cookie('localhost', access_cookie_key, access_cookie_value)
        response = self.client.post('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'msg': 'hello world'})

    def test_access_endpoints_with_cookies_and_csrf(self):
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True

        # Try without logging in
        response = self.client.post('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Login
        access_csrf, refresh_csrf = self._login()

        # Try with logging in but without double submit csrf protection
        response = self.client.post('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Try with logged in and bad header name for double submit token
        response = self.client.post('/api/protected',
                                   headers={'bad-header-name': 'banana'})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Try with logged in and bad header data for double submit token
        response = self.client.post('/api/protected',
                                   headers={'X-CSRF-TOKEN': 'banana'})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        # Try with logged in and good double submit token
        response = self.client.post('/api/protected',
                                   headers={'X-CSRF-TOKEN': access_csrf})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'msg': 'hello world'})

    def test_access_endpoints_with_cookie_missing_csrf_field(self):
        # Test accessing a csrf protected endpoint with a cookie that does not
        # have a csrf token in it
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = False
        self._login()
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True

        response = self.client.post('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)

    def test_access_endpoints_with_cookie_csrf_claim_not_string(self):
        now = datetime.utcnow()
        token_data = {
            'exp': now + timedelta(minutes=5),
            'iat': now,
            'nbf': now,
            'jti': 'banana',
            'identity': 'banana',
            'type': 'refresh',
            'csrf': 404
        }
        secret = self.app.secret_key
        algorithm = self.app.config['JWT_ALGORITHM']
        encoded_token = jwt.encode(token_data, secret, algorithm).decode('utf-8')
        access_cookie_key = self.app.config['JWT_ACCESS_COOKIE_NAME']
        self.client.set_cookie('localhost', access_cookie_key, encoded_token)

        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        response = self.client.post('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

    def test_custom_csrf_methods(self):
        @self.app.route('/protected-post', methods=['POST'])
        @jwt_required
        def protected_post():
            return jsonify({'msg': "hello world"})

        @self.app.route('/protected-get', methods=['GET'])
        @jwt_required
        def protected_get():
            return jsonify({'msg': "hello world"})

        # Login (saves jwts in the cookies for the test client
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        self._login()

        # Test being able to access GET without CSRF protection, and POST with
        # CSRF protection
        self.app.config['JWT_CSRF_METHODS'] = ['POST']

        response = self.client.post('/protected-post')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        response = self.client.get('/protected-get')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'msg': 'hello world'})

        # Now swap it around, and verify the JWT_CRSF_METHODS are being honored
        self.app.config['JWT_CSRF_METHODS'] = ['GET']

        response = self.client.get('/protected-get')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)

        response = self.client.post('/protected-post')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'msg': 'hello world'})


class TestEndpointsWithHeadersAndCookies(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        self.app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
        self.app.config['JWT_REFRESH_COOKIE_PATH'] = '/auth/refresh'
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route('/auth/login_cookies', methods=['POST'])
        def login_cookies():
            # Create the tokens we will be sending back to the user
            access_token = create_access_token(identity='test')
            refresh_token = create_refresh_token(identity='test')

            # Set the JWTs and the CSRF double submit protection cookies in this response
            resp = jsonify({'login': True})
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp, 200

        @self.app.route('/auth/login_headers', methods=['POST'])
        def login_headers():
            ret = {
                'access_token': create_access_token('test', fresh=True),
                'refresh_token': create_refresh_token('test')
            }
            return jsonify(ret), 200

        @self.app.route('/api/protected')
        @jwt_required
        def protected():
            return jsonify({'msg': "hello world"})

    def _jwt_post(self, url, jwt):
        response = self.client.post(url, content_type='application/json',
                                    headers={'Authorization': 'Bearer {}'.format(jwt)})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def _jwt_get(self, url, jwt, header_name='Authorization', header_type='Bearer'):
        header_type = '{} {}'.format(header_type, jwt).strip()
        response = self.client.get(url, headers={header_name: header_type})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def _login_cookies(self):
        resp = self.client.post('/auth/login_cookies')
        index = 1

        access_cookie_str = resp.headers[index][1]
        access_cookie_key = access_cookie_str.split('=')[0]
        access_cookie_value = "".join(access_cookie_str.split('=')[1:])
        self.client.set_cookie('localhost', access_cookie_key, access_cookie_value)
        index += 1

        if self.app.config['JWT_COOKIE_CSRF_PROTECT']:
            access_csrf_str = resp.headers[index][1]
            access_csrf_key = access_csrf_str.split('=')[0]
            access_csrf_value = "".join(access_csrf_str.split('=')[1:])
            self.client.set_cookie('localhost', access_csrf_key, access_csrf_value)
            index += 1
            access_csrf = access_csrf_value.split(';')[0]
        else:
            access_csrf = ""

        refresh_cookie_str = resp.headers[index][1]
        refresh_cookie_key = refresh_cookie_str.split('=')[0]
        refresh_cookie_value = "".join(refresh_cookie_str.split('=')[1:])
        self.client.set_cookie('localhost', refresh_cookie_key, refresh_cookie_value)
        index += 1

        if self.app.config['JWT_COOKIE_CSRF_PROTECT']:
            refresh_csrf_str = resp.headers[index][1]
            refresh_csrf_key = refresh_csrf_str.split('=')[0]
            refresh_csrf_value = "".join(refresh_csrf_str.split('=')[1:])
            self.client.set_cookie('localhost', refresh_csrf_key, refresh_csrf_value)
            refresh_csrf = refresh_csrf_value.split(';')[0]
        else:
            refresh_csrf = ""

        return access_csrf, refresh_csrf

    def _login_headers(self):
        resp = self.client.post('/auth/login_headers')
        data = json.loads(resp.get_data(as_text=True))
        return data['access_token'], data['refresh_token']

    def test_accessing_endpoint_with_headers(self):
        access_token, _ = self._login_headers()
        header_type = '{} {}'.format('Bearer', access_token).strip()
        response = self.client.get('/api/protected', headers={'Authorization': header_type})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'msg': 'hello world'})

    def test_accessing_endpoint_with_cookies(self):
        access_csrf, _ = self._login_cookies()
        response = self.client.get('/api/protected',
                                   headers={'X-CSRF-TOKEN': access_csrf})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'msg': 'hello world'})

    def test_accessing_endpoint_without_jwt(self):
        response = self.client.get('/api/protected')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 401)
        self.assertIn('msg', data)


# random 1024bit RSA keypair
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

class TestEndpointsWithAssymmetricCrypto(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = RSA_PRIVATE
        self.app.config['JWT_PUBLIC_KEY'] = RSA_PUBLIC
        self.app.config['JWT_ALGORITHM'] = 'RS256'
        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=1)
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=1)
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            ret = {
                'access_token': create_access_token('test', fresh=True),
                'refresh_token': create_refresh_token('test')
            }
            return jsonify(ret), 200

        @self.app.route('/auth/refresh', methods=['POST'])
        @jwt_refresh_token_required
        def refresh():
            username = get_jwt_identity()
            ret = {'access_token': create_access_token(username, fresh=False)}
            return jsonify(ret), 200

        @self.app.route('/auth/fresh-login', methods=['POST'])
        def fresh_login():
            ret = {'access_token': create_access_token('test', fresh=True)}
            return jsonify(ret), 200

        @self.app.route('/protected')
        @jwt_required
        def protected():
            return jsonify({'msg': "hello world"})

        @self.app.route('/fresh-protected')
        @fresh_jwt_required
        def fresh_protected():
            return jsonify({'msg': "fresh hello world"})

    def _jwt_post(self, url, jwt):
        response = self.client.post(url, content_type='application/json',
                                    headers={'Authorization': 'Bearer {}'.format(jwt)})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def _jwt_get(self, url, jwt, header_name='Authorization', header_type='Bearer'):
        header_type = '{} {}'.format(header_type, jwt).strip()
        response = self.client.get(url, headers={header_name: header_type})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def test_login(self):
        response = self.client.post('/auth/login')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)

    def test_fresh_login(self):
        response = self.client.post('/auth/fresh-login')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertNotIn('refresh_token', data)

    def test_refresh(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']
        refresh_token = data['refresh_token']

        status_code, data = self._jwt_post('/auth/refresh', refresh_token)
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertNotIn('refresh_token', data)
