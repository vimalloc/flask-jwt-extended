import json
import time
import unittest
from datetime import timedelta

from flask import Flask, jsonify
from flask_jwt_extended.utils import _encode_access_token
from flask_jwt_extended import JWTManager, create_refresh_access_tokens, \
    refresh_access_token, create_fresh_access_token, fresh_jwt_required, \
    jwt_required


# TODO test that config options in app.config successfully override defaults
# TODO move getting config options as helper methods in config.py


class TestEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=1)
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=1)
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            return create_refresh_access_tokens(identity='test')

        @self.app.route('/auth/refresh', methods=['POST'])
        def refresh():
            return refresh_access_token()

        @self.app.route('/auth/fresh-login', methods=['POST'])
        def fresh_login():
            return create_fresh_access_token(identity='test')

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

    def _jwt_get(self, url, jwt):
        auth_header = 'Bearer {}'.format(jwt)
        response = self.client.get(url, headers={'Authorization': auth_header})
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
            return create_fresh_access_token('foobar')

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
            token = _encode_access_token('foo', 'newsecret', 'HS256',
                                         timedelta(minutes=5), True, {})
        auth_header = "Bearer {}".format(token)
        response = self.client.get('/protected', headers={'Authorization': auth_header})
        data = json.loads(response.get_data(as_text=True))
        status_code = response.status_code
        self.assertEqual(status_code, 422)
        self.assertIn('msg', data)
