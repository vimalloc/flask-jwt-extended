import json
import unittest
from datetime import timedelta

from flask import Flask
from flask_jwt_extended import JWTManager, create_refresh_access_tokens, \
    refresh_access_token, create_fresh_access_token, fresh_jwt_required, \
    jwt_required


# TODO test that config options in app.config successfully override defaults
# TODO move getting config options as helper methods in config.py


class TestEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=3)
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=6)
        self.jwt_manager = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route('/auth/login', methods=['POST'])
        def login():
            return create_refresh_access_tokens(identity='test')

        @self.app.route('/auth/refresh', methods=['POST'])
        def refresh():
            return refresh_access_token()

        @self.app.route('/auth/fresh-login', methods=['POST'])
        def fresh_lobin():
            return create_fresh_access_token(identity='test')

        @jwt_required
        def protected():
            return 'hello'

        @fresh_jwt_required
        def fresh_protected():
            return 'fresh protected'

    def test_login(self):
        response = self.client.post('/auth/login')
        status_code = response.status_code
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(status_code, 200)
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
