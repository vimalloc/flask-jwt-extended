import unittest

from flask import Flask, jsonify, json

from flask_jwt_extended import JWTManager, create_access_token, jwt_required


class TestUserClaimsVerification(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.jwt_manager.claims_verification_loader
        def claims_verification(user_claims):
            expected_keys = ['foo', 'bar']
            for key in expected_keys:
                if key not in user_claims:
                    return False
            return True

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            ret = {'access_token': create_access_token('test')}
            return jsonify(ret), 200

        @self.app.route('/protected')
        @jwt_required
        def protected():
            return jsonify({'msg': "hello world"})

    def _jwt_get(self, url, jwt, header_name='Authorization', header_type='Bearer'):
        header_type = '{} {}'.format(header_type, jwt).strip()
        response = self.client.get(url, headers={header_name: header_type})
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def test_valid_user_claims(self):
        @self.jwt_manager.user_claims_loader
        def user_claims_callback(identity):
            return {'foo': 'baz', 'bar': 'boom'}

        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(data, {'msg': 'hello world'})
        self.assertEqual(status, 200)

    def test_empty_claims_verification_error(self):
        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(data, {'msg': 'User claims verification failed'})
        self.assertEqual(status, 400)

    def test_bad_claims_verification_error(self):
        @self.jwt_manager.user_claims_loader
        def user_claims_callback(identity):
            return {'super': 'banana'}

        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(data, {'msg': 'User claims verification failed'})
        self.assertEqual(status, 400)

    def test_bad_claims_custom_error_callback(self):
        @self.jwt_manager.claims_verification_failed_loader
        def user_claims_callback():
            return jsonify({'foo': 'bar'}), 404

        response = self.client.post('/auth/login')
        data = json.loads(response.get_data(as_text=True))
        access_token = data['access_token']

        status, data = self._jwt_get('/protected', access_token)
        self.assertEqual(data, {'foo': 'bar'})
        self.assertEqual(status, 404)
