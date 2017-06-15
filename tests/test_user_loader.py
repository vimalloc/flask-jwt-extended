import json
import unittest
from datetime import timedelta

from flask import Flask, jsonify, request

from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_refresh_token_required, jwt_required, fresh_jwt_required,
    jwt_optional, current_user
)


class TestUserLoader(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.jwt_manager.user_loader_callback_loader
        def user_loader(identity):
            if identity == 'foobar':
                return None
            return identity

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            username = request.get_json()['username']
            ret = {
                'access_token': create_access_token(username, fresh=True),
                'refresh_token': create_refresh_token(username)
            }
            return jsonify(ret), 200

        @self.app.route('/refresh-protected')
        @jwt_refresh_token_required
        def refresh_endpoint():
            return jsonify({'username': str(current_user)})

        @self.app.route('/protected')
        @jwt_required
        def protected_endpoint():
            return jsonify({'username': str(current_user)})

        @self.app.route('/fresh-protected')
        @fresh_jwt_required
        def fresh_protected_endpoint():
            return jsonify({'username': str(current_user)})

        @self.app.route('/partially-protected')
        @jwt_optional
        def optional_endpoint():
            return jsonify({'username': str(current_user)})

    def _jwt_get(self, url, jwt):
        response = self.client.get(url, content_type='application/json',
                                   headers={'Authorization': 'Bearer {}'.format(jwt)})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def test_user_loads(self):
        response = self.client.post('/auth/login', content_type='application/json',
                                    data=json.dumps({'username': 'test'}))
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']
        refresh_token = data['refresh_token']

        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(status, 200)
        self.assertEqual(data, {'username': 'test'})

        status, data = self._jwt_get('/fresh-protected', access_token)
        self.assertEqual(status, 200)
        self.assertEqual(data, {'username': 'test'})

        status, data = self._jwt_get('/partially-protected', access_token)
        self.assertEqual(status, 200)
        self.assertEqual(data, {'username': 'test'})

        status, data = self._jwt_get('/refresh-protected', refresh_token)
        self.assertEqual(status, 200)
        self.assertEqual(data, {'username': 'test'})

    def test_failed_user_loads(self):
        response = self.client.post('/auth/login', content_type='application/json',
                                    data=json.dumps({'username': 'foobar'}))
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']
        refresh_token = data['refresh_token']

        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(status, 401)
        self.assertEqual(data, {'msg': 'Error loading the user foobar'})

        status, data = self._jwt_get('/fresh-protected', access_token)
        self.assertEqual(status, 401)
        self.assertEqual(data, {'msg': 'Error loading the user foobar'})

        status, data = self._jwt_get('/partially-protected', access_token)
        self.assertEqual(status, 401)
        self.assertEqual(data, {'msg': 'Error loading the user foobar'})

        status, data = self._jwt_get('/refresh-protected', refresh_token)
        self.assertEqual(status, 401)
        self.assertEqual(data, {'msg': 'Error loading the user foobar'})

    def test_custom_error_callback(self):
        @self.jwt_manager.user_loader_error_loader
        def custom_user_loader_error_callback(identity):
            return jsonify({"msg": "Not found"}), 404

        response = self.client.post('/auth/login', content_type='application/json',
                                    data=json.dumps({'username': 'foobar'}))
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']
        refresh_token = data['refresh_token']

        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(status, 404)
        self.assertEqual(data, {'msg': 'Not found'})

        status, data = self._jwt_get('/fresh-protected', access_token)
        self.assertEqual(status, 404)
        self.assertEqual(data, {'msg': 'Not found'})

        status, data = self._jwt_get('/partially-protected', access_token)
        self.assertEqual(status, 404)
        self.assertEqual(data, {'msg': 'Not found'})

        status, data = self._jwt_get('/refresh-protected', refresh_token)
        self.assertEqual(status, 404)
        self.assertEqual(data, {'msg': 'Not found'})
