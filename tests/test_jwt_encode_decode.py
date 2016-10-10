import unittest
import calendar
from datetime import datetime, timedelta

import jwt
from flask import Flask
from flask_jwt_extended.exceptions import JWTEncodeError, JWTDecodeError
from flask_jwt_extended.utils import _encode_access_token, _encode_refresh_token, \
    _decode_jwt


class JWTEncodeDecodeTests(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)

    def test_jwt_identity(self):
        pass

    def test_jwt_claims(self):
        pass

    def test_encode_access_token(self):
        secret = 'super-totally-secret-key'
        algorithm = 'HS256'
        token_expire_delta = timedelta(minutes=5)
        user_claims = {'foo': 'bar'}

        # Check with a fresh token
        with self.app.test_request_context():
            identity = 'user1'
            token = _encode_access_token(identity, secret, algorithm, token_expire_delta,
                                         fresh=True, user_claims=user_claims)
            data = jwt.decode(token, secret, algorithm=algorithm)
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('identity', data)
            self.assertIn('fresh', data)
            self.assertIn('type', data)
            self.assertIn('user_claims', data)
            self.assertEqual(data['identity'], identity)
            self.assertEqual(data['fresh'], True)
            self.assertEqual(data['type'], 'access')
            self.assertEqual(data['user_claims'], user_claims)
            self.assertEqual(data['iat'], data['nbf'])
            now_ts = calendar.timegm(datetime.utcnow().utctimetuple())
            exp_seconds = data['exp'] - now_ts
            self.assertLessEqual(exp_seconds, 60 * 5)
            self.assertGreater(exp_seconds, 60 * 4)

            # Check with a non-fresh token
            identity = 12345  # identity can be anything json serializable
            token = _encode_access_token(identity, secret, algorithm, token_expire_delta,
                                         fresh=False, user_claims=user_claims)
            data = jwt.decode(token, secret, algorithm=algorithm)
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('identity', data)
            self.assertIn('fresh', data)
            self.assertIn('type', data)
            self.assertIn('user_claims', data)
            self.assertEqual(data['identity'], identity)
            self.assertEqual(data['fresh'], False)
            self.assertEqual(data['type'], 'access')
            self.assertEqual(data['user_claims'], user_claims)
            self.assertEqual(data['iat'], data['nbf'])
            now_ts = calendar.timegm(datetime.utcnow().utctimetuple())
            exp_seconds = data['exp'] - now_ts
            self.assertLessEqual(exp_seconds, 60 * 5)
            self.assertGreater(exp_seconds, 60 * 4)

    def test_encode_invalid_access_token(self):
        # Check with non-serializable json
        with self.app.test_request_context():
            user_claims = datetime
            with self.assertRaises(JWTEncodeError):
                _encode_access_token('user1', 'secret', 'HS256',
                                     timedelta(hours=1), True, user_claims)

            user_claims = "banana"
            with self.assertRaises(JWTEncodeError):
                _encode_access_token('user1', 'secret', 'HS256',
                                     timedelta(hours=1), True, user_claims)

            user_claims = {'foo': timedelta(hours=4)}
            with self.assertRaises(JWTEncodeError):
                _encode_access_token('user1', 'secret', 'HS256',
                                     timedelta(hours=1), True, user_claims)

            with self.assertRaises(JWTEncodeError):
                _encode_access_token('user1', 'secret', 'HS256',
                                     timedelta(hours=1), 'not_a_bool', {})

    def test_encode_refresh_token(self):
        secret = 'super-totally-secret-key'
        algorithm = 'HS256'
        token_expire_delta = timedelta(minutes=5)

        # Check with a fresh token
        with self.app.test_request_context():
            identity = 'user1'
            token = _encode_refresh_token(identity, secret, algorithm, token_expire_delta)
            data = jwt.decode(token, secret, algorithm=algorithm)
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('type', data)
            self.assertIn('identity', data)
            self.assertEqual(data['identity'], identity)
            self.assertEqual(data['type'], 'refresh')
            self.assertEqual(data['iat'], data['nbf'])
            now_ts = calendar.timegm(datetime.utcnow().utctimetuple())
            exp_seconds = data['exp'] - now_ts
            self.assertLessEqual(exp_seconds, 60 * 5)
            self.assertGreater(exp_seconds, 60 * 4)

            # Check with a non-fresh token
            identity = 12345  # identity can be anything json serializable
            token = _encode_refresh_token(identity, secret, algorithm, token_expire_delta)
            data = jwt.decode(token, secret, algorithm=algorithm)
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('type', data)
            self.assertIn('identity', data)
            self.assertEqual(data['identity'], identity)
            self.assertEqual(data['type'], 'refresh')
            self.assertEqual(data['iat'], data['nbf'])
            now_ts = calendar.timegm(datetime.utcnow().utctimetuple())
            exp_seconds = data['exp'] - now_ts
            self.assertLessEqual(exp_seconds, 60 * 5)
            self.assertGreater(exp_seconds, 60 * 4)

    def test_decode_jwt(self):
        # Test decoding a valid access token
        with self.app.test_request_context():
            now = datetime.utcnow()
            now_ts = calendar.timegm(now.utctimetuple())
            token_data = {
                'exp': now + timedelta(minutes=5),
                'iat': now,
                'nbf': now,
                'jti': 'banana',
                'identity': 'banana',
                'fresh': True,
                'type': 'access',
                'user_claims': {'foo': 'bar'},
            }
            encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
            data = _decode_jwt(encoded_token, 'secret', 'HS256')
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('identity', data)
            self.assertIn('fresh', data)
            self.assertIn('type', data)
            self.assertIn('user_claims', data)
            self.assertEqual(data['exp'], now_ts + (5 * 60))
            self.assertEqual(data['iat'], now_ts)
            self.assertEqual(data['nbf'], now_ts)
            self.assertEqual(data['jti'], 'banana')
            self.assertEqual(data['identity'], 'banana')
            self.assertEqual(data['fresh'], True)
            self.assertEqual(data['type'], 'access')
            self.assertEqual(data['user_claims'], {'foo': 'bar'})

        # Test decoding a valid refresh token
        with self.app.test_request_context():
            now = datetime.utcnow()
            now_ts = calendar.timegm(now.utctimetuple())
            token_data = {
                'exp': now + timedelta(minutes=5),
                'iat': now,
                'nbf': now,
                'jti': 'banana',
                'identity': 'banana',
                'type': 'refresh',
            }
            encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
            data = _decode_jwt(encoded_token, 'secret', 'HS256')
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('identity', data)
            self.assertIn('type', data)
            self.assertEqual(data['exp'], now_ts + (5 * 60))
            self.assertEqual(data['iat'], now_ts)
            self.assertEqual(data['nbf'], now_ts)
            self.assertEqual(data['jti'], 'banana')
            self.assertEqual(data['identity'], 'banana')
            self.assertEqual(data['type'], 'refresh')

    def test_decode_invalid_jwt(self):
        with self.app.test_request_context():
            # Verify underlying pyjwt expires verification works
            with self.assertRaises(jwt.ExpiredSignatureError):
                token_data = {
                    'exp': datetime.utcnow() - timedelta(minutes=5),
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Missing jti
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'identity': 'banana',
                    'type': 'refresh'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Missing identity
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'refresh'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Missing type
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'identity': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Missing fresh in access token
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'identity': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'access',
                    'user_claims': {}
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Bad fresh in access token
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'identity': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'access',
                    'user_claims': {},
                    'fresh': 'banana'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Missing user claims in access token
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'identity': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'access',
                    'fresh': True
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Bad user claims
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'identity': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'access',
                    'fresh': True,
                    'user_claims': 'banana'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            # Bad token type
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'identity': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'banana',
                    'fresh': True,
                    'user_claims': 'banana'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

        # Missing and bad csrf tokens
        self.app.config['JWT_TOKEN_LOCATION'] = 'cookies'
        self.app.config['JWT_COOKIE_CSRF_PROTECTION'] = True
        with self.app.test_request_context():
            now = datetime.utcnow()
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'exp': now + timedelta(minutes=5),
                    'iat': now,
                    'nbf': now,
                    'jti': 'banana',
                    'identity': 'banana',
                    'type': 'refresh',
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')

            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'exp': now + timedelta(minutes=5),
                    'iat': now,
                    'nbf': now,
                    'jti': 'banana',
                    'identity': 'banana',
                    'type': 'refresh',
                    'csrf': True
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                _decode_jwt(encoded_token, 'secret', 'HS256')
