import unittest

import json

import simplekv.memory
from flask import Flask, jsonify, request

from flask_jwt_extended import JWTManager, create_refresh_access_tokens, \
    get_all_stored_tokens, get_stored_tokens, revoke_token, unrevoke_token


class TestEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.app.config['JWT_BLACKLIST_ENABLED'] = True
        self.app.config['JWT_BLACKLIST_STORE'] = simplekv.memory.DictStore()
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            username = request.json['username']
            return create_refresh_access_tokens(identity=username)

        @self.app.route('/auth/tokens/<identity>', methods=['GET'])
        def list_identity_tokens(identity):
            return jsonify(get_stored_tokens(identity)), 200

        @self.app.route('/auth/tokens', methods=['GET'])
        def list_all_tokens():
            return jsonify(get_all_stored_tokens()), 200

        @self.app.route('/auth/revoke/<jti>', methods=['POST'])
        def revoke(jti):
            revoke_token(jti)
            return jsonify({"msg": "Token revoked"})

        @self.app.route('/auth/unrevoke/<jti>', methods=['POST'])
        def unrevoke(jti):
            unrevoke_token(jti)
            return jsonify({"msg": "Token unrevoked"})

    def _login(self, username):
        post_data = {'username': username}
        response = self.client.post('/auth/login', data=json.dumps(post_data),
                                    content_type='application/json')
        data = json.loads(response.get_data(as_text=True))
        return data['access_token'], data['refresh_token']

    def _jwt_post(self, url):
        response = self.client.post(url, content_type='application/json')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def test_revoke_unrevoke_all_token(self):
        # Check access and refersh tokens
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'all'

        # No tokens initially
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data, [])

        # Login, now should have two tokens (access and refresh) that are not revoked
        self._login('test1')
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 2)
        self.assertFalse(data[0]['revoked'])
        self.assertFalse(data[1]['revoked'])

        # Revoke the access token
        access_jti = [x['token']['jti'] for x in data if x['token']['type'] == 'access'][0]
        status, data = self._jwt_post('/auth/revoke/{}'.format(access_jti))
        self.assertEqual(status, 200)
        self.assertIn('msg', data)

        # Verify the access token has been revoked on new lookup
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 2)
        if data[0]['token']['jti'] == access_jti:
            self.assertTrue(data[0]['revoked'])
            self.assertFalse(data[1]['revoked'])
        else:
            self.assertFalse(data[0]['revoked'])
            self.assertTrue(data[1]['revoked'])

        # Unrevoke the access token
        status, data = self._jwt_post('/auth/unrevoke/{}'.format(access_jti))
        self.assertEqual(status, 200)
        self.assertIn('msg', data)

        # Make sure token is marked as unrevoked
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 2)
        self.assertFalse(data[0]['revoked'])
        self.assertFalse(data[1]['revoked'])

    def test_revoke_unrevoke_refresh_token(self):
        # Check only refresh tokens
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'

        # No tokens initially
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data, [])

        # Login, now should have one token that is not revoked
        self._login('test1')
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 1)
        self.assertFalse(data[0]['revoked'])

        # Revoke the token
        refresh_jti = data[0]['token']['jti']
        status, data = self._jwt_post('/auth/revoke/{}'.format(refresh_jti))
        self.assertEqual(status, 200)
        self.assertIn('msg', data)

        # Verify the token has been revoked on new lookup
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 1)
        self.assertTrue(data[0]['revoked'])

        # Unrevoke the token
        status, data = self._jwt_post('/auth/unrevoke/{}'.format(refresh_jti))
        self.assertEqual(status, 200)
        self.assertIn('msg', data)

        # Make sure token is marked as unrevoked
        response = self.client.get('/auth/tokens')
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 1)
        self.assertFalse(data[0]['revoked'])

    def test_revoked_access_token(self):
        pass

    def test_revoked_refresh_token(self):
        pass
