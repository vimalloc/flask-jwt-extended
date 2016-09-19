import unittest
import json

from flask import Flask, jsonify
from flask_jwt_extended import JWTManager


class TestJWTManager(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)

    def _parse_callback_result(self, result):
        """
        Returns a tuple, where the first item is http status code and
        the second is the data (via json.loads)
        """
        response = result[0]
        status_code = result[1]
        data = json.loads(response.get_data(as_text=True))
        return status_code, data

    def test_init_app(self):
        jwt_manager = JWTManager()
        jwt_manager.init_app(self.app)
        self.assertIsInstance(jwt_manager, JWTManager)

    def test_class_init(self):
        jwt_manager = JWTManager(self.app)
        self.assertIsInstance(jwt_manager, JWTManager)

    def test_default_user_claims_callback(self):
        m = JWTManager(self.app)
        assert m.user_claims_callback() == {}

    def test_default_expired_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m.expired_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 401)
            self.assertEquals(data, {'msg': 'Token has expired'})

    def test_default_invalid_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            err = "Test error"
            result = m.invalid_token_callback(err)
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 422)
            self.assertEquals(data, {'msg': err})

    def test_default_unauthorized_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m.unauthorized_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 401)
            self.assertEquals(data, {'msg': 'Missing Authorization Header'})

    def test_default_token_needs_refresh_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m.token_needs_refresh_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 401)
            self.assertEquals(data, {'msg': 'Fresh token required'})

    def test_default_revoked_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m.revoked_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 401)
            self.assertEquals(data, {'msg': 'Token has been revoked'})

    def test_custom_user_claims_callback(self):
        m = JWTManager(self.app)

        @m.user_claims_loader
        def custom_user_claims():
            return {'foo': 'bar'}

        assert m.user_claims_callback() == {'foo': 'bar'}

    def test_custom_expired_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.expired_token_loader
            def custom_expired_token():
                return jsonify({"res": "TOKEN IS EXPIRED FOOL"}), 422

            result = m.expired_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 422)
            self.assertEquals(data, {'res': 'TOKEN IS EXPIRED FOOL'})

    def test_custom_invalid_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            err = "Test error"

            @m.invalid_token_loader
            def custom_invalid_token(err):
                return jsonify({"err": err}), 200

            result = m.invalid_token_callback(err)
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 200)
            self.assertEquals(data, {'err': err})

    def test_custom_unauthorized_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.unauthorized_loader
            def custom_unauthorized():
                return jsonify({"err": "GOTTA LOGIN FOOL"}), 200

            result = m.unauthorized_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 200)
            self.assertEquals(data, {'err': 'GOTTA LOGIN FOOL'})

    def test_custom_token_needs_refresh_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.token_needs_refresh_loader
            def custom_token_needs_refresh():
                return jsonify({'sub_status': 101}), 200

            result = m.token_needs_refresh_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 200)
            self.assertEquals(data, {'sub_status': 101})

    def test_custom_revoked_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.revoked_token_loader
            def custom_revoken_token():
                return jsonify({"err": "Nice knowing you!"}), 422
            result = m.revoked_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEquals(status_code, 422)
            self.assertEquals(data, {'err': 'Nice knowing you!'})
