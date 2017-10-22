import unittest
import json

from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_jwt_extended.utils import has_user_loader


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
        self.assertEqual(jwt_manager, self.app.extensions['flask-jwt-extended'])

    def test_class_init(self):
        jwt_manager = JWTManager(self.app)
        self.assertEqual(jwt_manager, self.app.extensions['flask-jwt-extended'])

    def test_default_user_claims_callback(self):
        identity = 'foobar'
        m = JWTManager(self.app)
        self.assertEqual(m._user_claims_callback(identity), {})

    def test_default_user_identity_callback(self):
        identity = 'foobar'
        m = JWTManager(self.app)
        self.assertEqual(m._user_identity_callback(identity), identity)

    def test_default_expired_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m._expired_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 401)
            self.assertEqual(data, {'msg': 'Token has expired'})

    def test_default_invalid_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            err = "Test error"
            result = m._invalid_token_callback(err)
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 422)
            self.assertEqual(data, {'msg': err})

    def test_default_unauthorized_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m._unauthorized_callback("Missing Authorization Header")
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 401)
            self.assertEqual(data, {'msg': 'Missing Authorization Header'})

    def test_default_needs_fresh_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m._needs_fresh_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 401)
            self.assertEqual(data, {'msg': 'Fresh token required'})

    def test_default_revoked_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            result = m._revoked_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 401)
            self.assertEqual(data, {'msg': 'Token has been revoked'})

    def test_default_user_loader_callback(self):
        m = JWTManager(self.app)
        self.assertEqual(m._user_loader_callback, None)

    def test_default_user_loader_error_callback(self):
        with self.app.test_request_context():
            identity = 'foobar'
            m = JWTManager(self.app)
            result = m._user_loader_error_callback(identity)
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 401)
            self.assertEqual(data, {'msg': 'Error loading the user foobar'})

    def test_default_has_user_loader(self):
        m = JWTManager(self.app)
        with self.app.app_context():
            self.assertEqual(has_user_loader(), False)

    def test_custom_user_claims_callback(self):
        identity = 'foobar'
        m = JWTManager(self.app)

        @m.user_claims_loader
        def custom_user_claims(identity):
            return {'foo': 'bar'}

        assert m._user_claims_callback(identity) == {'foo': 'bar'}

    def test_custom_expired_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.expired_token_loader
            def custom_expired_token():
                return jsonify({"res": "TOKEN IS EXPIRED FOOL"}), 422

            result = m._expired_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 422)
            self.assertEqual(data, {'res': 'TOKEN IS EXPIRED FOOL'})

    def test_custom_invalid_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)
            err = "Test error"

            @m.invalid_token_loader
            def custom_invalid_token(err):
                return jsonify({"err": err}), 200

            result = m._invalid_token_callback(err)
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 200)
            self.assertEqual(data, {'err': err})

    def test_custom_unauthorized_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.unauthorized_loader
            def custom_unauthorized(err_str):
                return jsonify({"err": err_str}), 200

            result = m._unauthorized_callback("GOTTA LOGIN FOOL")
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 200)
            self.assertEqual(data, {'err': 'GOTTA LOGIN FOOL'})

    def test_custom_needs_fresh_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.needs_fresh_token_loader
            def custom_token_needs_refresh():
                return jsonify({'sub_status': 101}), 200

            result = m._needs_fresh_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 200)
            self.assertEqual(data, {'sub_status': 101})

    def test_custom_revoked_token_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.revoked_token_loader
            def custom_revoken_token():
                return jsonify({"err": "Nice knowing you!"}), 422
            result = m._revoked_token_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 422)
            self.assertEqual(data, {'err': 'Nice knowing you!'})

    def test_custom_user_loader(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.user_loader_callback_loader
            def custom_user_loader(identity):
                if identity == 'foo':
                    return None
                return identity

            identity = 'foobar'
            result = m._user_loader_callback(identity)
            self.assertEqual(result, identity)
            self.assertEqual(has_user_loader(), True)

    def test_custom_user_loader_error_callback(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.user_loader_error_loader
            def custom_user_loader_error(identity):
                return jsonify({'msg': 'Not found'}), 404

            identity = 'foobar'
            result = m._user_loader_error_callback(identity)
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 404)
            self.assertEqual(data, {'msg': 'Not found'})

    def test_claims_verification(self):
        with self.app.test_request_context():
            m = JWTManager(self.app)

            @m.claims_verification_loader
            def user_claims_verification(claims):
                return 'foo' in claims

            @m.claims_verification_failed_loader
            def user_claims_verification_failed():
                return jsonify({'msg': 'Test'}), 404

            result = m._claims_verification_callback({'bar': 'baz'})
            self.assertEqual(result, False)

            result = m._claims_verification_failed_callback()
            status_code, data = self._parse_callback_result(result)

            self.assertEqual(status_code, 404)
            self.assertEqual(data, {'msg': 'Test'})
