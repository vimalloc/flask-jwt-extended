import unittest
import json

from flask import Flask, jsonify, request
from flask_jwt_extended.utils import get_jwt_identity, get_jti

from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, create_refresh_token,
    jwt_refresh_token_required, fresh_jwt_required
)


class TestEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.app.config['JWT_BLACKLIST_ENABLED'] = True
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()
        self.blacklist = set()

        @self.jwt_manager.token_in_blacklist_loader
        def token_in_blacklist(decoded_token):
            jti = decoded_token['jti']
            return jti in self.blacklist

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            username = request.get_json()['username']
            ret = {
                'access_token': create_access_token(username, fresh=True),
                'refresh_token': create_refresh_token(username)
            }
            return jsonify(ret), 200

        @self.app.route('/auth/refresh', methods=['POST'])
        @jwt_refresh_token_required
        def refresh():
            username = get_jwt_identity()
            ret = {'access_token': create_access_token(username, fresh=False)}
            return jsonify(ret), 200

        @self.app.route('/auth/revoke/<jti>', methods=['POST'])
        def revoke(jti):
            self.blacklist.add(jti)
            return jsonify({"msg": "Token revoked"})

        @self.app.route('/auth/unrevoke/<jti>', methods=['POST'])
        def unrevoke(jti):
            self.blacklist.remove(jti)
            return jsonify({"msg": "Token unrevoked"})

        @self.app.route('/protected', methods=['POST'])
        @jwt_required
        def protected():
            return jsonify({"hello": "world"})

        @self.app.route('/protected-fresh', methods=['POST'])
        @fresh_jwt_required
        def protected_fresh():
            return jsonify({"hello": "world"})

    def _login(self, username):
        post_data = {'username': username}
        response = self.client.post('/auth/login', data=json.dumps(post_data),
                                    content_type='application/json')
        data = json.loads(response.get_data(as_text=True))
        return data['access_token'], data['refresh_token']

    def _jwt_post(self, url, jwt=None):
        if jwt:
            header = {'Authorization': 'Bearer {}'.format(jwt)}
            response = self.client.post(url, headers=header)
        else:
            response = self.client.post(url)
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def test_revoke_access_token(self):
        # Check access and refresh tokens
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

        # Generate our tokens
        access_token, _ = self._login('user')
        with self.app.app_context():
            access_jti = get_jti(access_token)

        # Make sure we can access a protected endpoint
        status_code, data = self._jwt_post('/protected', access_token)
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'hello': 'world'})

        # Revoke our access token
        status, data = self._jwt_post('/auth/revoke/{}'.format(access_jti))
        self.assertEqual(status, 200)
        self.assertEqual(data, {'msg': 'Token revoked'})

        # Verify the access token can no longer access a protected endpoint
        status_code, data = self._jwt_post('/protected', access_token)
        self.assertEqual(status_code, 401)
        self.assertEqual(data, {'msg': 'Token has been revoked'})

    def test_revoke_refresh_token(self):
        # Check access and refresh tokens
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

        # Generate our tokens
        _, refresh_token = self._login('user')
        with self.app.app_context():
            refresh_jti = get_jti(refresh_token)

        # Make sure we can access a protected endpoint
        status_code, data = self._jwt_post('/auth/refresh', refresh_token)
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)

        # Revoke our access token
        status, data = self._jwt_post('/auth/revoke/{}'.format(refresh_jti))
        self.assertEqual(status, 200)
        self.assertEqual(data, {'msg': 'Token revoked'})

        # Verify the access token can no longer access a protected endpoint
        status_code, data = self._jwt_post('/auth/refresh', refresh_token)
        self.assertEqual(status_code, 401)
        self.assertEqual(data, {'msg': 'Token has been revoked'})

    def test_revoked_token_with_access_blacklist_only(self):
        # Setup to only revoke refresh tokens
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['refresh']

        # Generate our tokens
        access_token, refresh_token = self._login('user')
        with self.app.app_context():
            access_jti = get_jti(access_token)
            refresh_jti = get_jti(refresh_token)

        # Revoke both tokens (even though app is only configured to look
        # at revoked refresh tokens)
        self._jwt_post('/auth/revoke/{}'.format(access_jti))
        self._jwt_post('/auth/revoke/{}'.format(refresh_jti))

        # Make sure we can still access a protected endpoint with the access token
        status_code, data = self._jwt_post('/protected', access_token)
        self.assertEqual(status_code, 200)
        self.assertEqual(data, {'hello': 'world'})

        # Make sure that the refresh token kicks us back out
        status_code, data = self._jwt_post('/auth/refresh', refresh_token)
        self.assertEqual(status_code, 401)
        self.assertEqual(data, {'msg': 'Token has been revoked'})

    def test_bad_blacklist_settings(self):
        # Disable the token in blacklist check function
        self.jwt_manager.token_in_blacklist_loader(None)

        access_token, _ = self._login('user')

        # Check that accessing a jwt_required endpoint raises a runtime error
        with self.assertRaises(RuntimeError):
            self._jwt_post('/protected', access_token)

        # Check calling blacklist function if invalid blacklist check type
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'banana']
        with self.assertRaises(RuntimeError):
            self._jwt_post('/protected', access_token)
