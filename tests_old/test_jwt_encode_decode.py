import unittest
import calendar
from datetime import datetime, timedelta

import jwt
from flask import Flask
from flask_jwt_extended.exceptions import JWTDecodeError
from flask_jwt_extended.tokens import (
    encode_access_token, encode_refresh_token,
    decode_jwt
)
from flask_jwt_extended.utils import create_access_token, create_refresh_token
from flask_jwt_extended.jwt_manager import JWTManager


class JWTEncodeDecodeTests(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.jwt = JWTManager(self.app)

    def test_jwt_identity(self):
        pass

    def test_jwt_claims(self):
        pass

    def test_encode_access_token(self):
        secret = 'super-totally-secret-key'
        algorithm = 'HS256'
        token_expire_delta = timedelta(minutes=5)
        user_claims = {'foo': 'bar'}
        identity_claim = 'identity'

        # Check with a fresh token
        with self.app.test_request_context():
            identity = 'user1'
            token = encode_access_token(identity, secret, algorithm, token_expire_delta,
                                        fresh=True, user_claims=user_claims, csrf=False,
                                        identity_claim=identity_claim)
            data = jwt.decode(token, secret, algorithms=[algorithm])
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn(identity_claim, data)
            self.assertIn('fresh', data)
            self.assertIn('type', data)
            self.assertIn('user_claims', data)
            self.assertNotIn('csrf', data)
            self.assertEqual(data[identity_claim], identity)
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
            token = encode_access_token(identity, secret, algorithm, token_expire_delta,
                                        fresh=False, user_claims=user_claims, csrf=True,
                                        identity_claim=identity_claim)
            data = jwt.decode(token, secret, algorithms=[algorithm])
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn(identity_claim, data)
            self.assertIn('fresh', data)
            self.assertIn('type', data)
            self.assertIn('user_claims', data)
            self.assertIn('csrf', data)
            self.assertEqual(data[identity_claim], identity)
            self.assertEqual(data['fresh'], False)
            self.assertEqual(data['type'], 'access')
            self.assertEqual(data['user_claims'], user_claims)
            self.assertEqual(data['iat'], data['nbf'])
            now_ts = calendar.timegm(datetime.utcnow().utctimetuple())
            exp_seconds = data['exp'] - now_ts
            self.assertLessEqual(exp_seconds, 60 * 5)
            self.assertGreater(exp_seconds, 60 * 4)

    def test_encode_access_token__no_user_claims(self):
        '''
        To make JWT shorter, do not add `user_claims` if empty.
        '''
        secret = 'super-totally-secret-key'
        algorithm = 'HS256'
        token_expire_delta = timedelta(minutes=5)
        identity_claim = 'sub'

        # `user_claims` is empty dict
        with self.app.test_request_context():
            identity = 'user1'
            token = encode_access_token(identity, secret, algorithm, token_expire_delta,
                                        fresh=False, user_claims={}, csrf=False,
                                        identity_claim=identity_claim)

            data = jwt.decode(token, secret, algorithms=[algorithm])
            self.assertNotIn('user_claims', data)

        # `user_claims` is None
        with self.app.test_request_context():
            identity = 'user1'
            token = encode_access_token(identity, secret, algorithm, token_expire_delta,
                                        fresh=False, user_claims=None, csrf=False,
                                        identity_claim=identity_claim)

            data = jwt.decode(token, secret, algorithms=[algorithm])
            self.assertNotIn('user_claims', data)

    def test_encode_invalid_access_token(self):
        # Check with non-serializable json
        with self.app.test_request_context():
            user_claims = datetime
            identity_claim = 'identity'
            with self.assertRaises(Exception):
                encode_access_token('user1', 'secret', 'HS256',
                                    timedelta(hours=1), True, user_claims,
                                    csrf=True, identity_claim=identity_claim)

            user_claims = {'foo': timedelta(hours=4)}
            with self.assertRaises(Exception):
                encode_access_token('user1', 'secret', 'HS256',
                                    timedelta(hours=1), True, user_claims,
                                    csrf=True, identity_claim=identity_claim)

    def test_encode_refresh_token(self):
        secret = 'super-totally-secret-key'
        algorithm = 'HS256'
        token_expire_delta = timedelta(minutes=5)
        identity_claim = 'sub'

        # Check with a fresh token
        with self.app.test_request_context():
            identity = 'user1'
            token = encode_refresh_token(identity, secret, algorithm,
                                         token_expire_delta, csrf=False,
                                         identity_claim=identity_claim)
            data = jwt.decode(token, secret, algorithms=[algorithm])
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('type', data)
            self.assertIn(identity_claim, data)
            self.assertNotIn('csrf', data)
            self.assertEqual(data[identity_claim], identity)
            self.assertEqual(data['type'], 'refresh')
            self.assertEqual(data['iat'], data['nbf'])
            now_ts = calendar.timegm(datetime.utcnow().utctimetuple())
            exp_seconds = data['exp'] - now_ts
            self.assertLessEqual(exp_seconds, 60 * 5)
            self.assertGreater(exp_seconds, 60 * 4)

            # Check with a csrf token
            identity = 12345  # identity can be anything json serializable
            token = encode_refresh_token(identity, secret, algorithm,
                                         token_expire_delta, csrf=True,
                                         identity_claim=identity_claim)
            data = jwt.decode(token, secret, algorithms=[algorithm])
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn('type', data)
            self.assertIn('csrf', data)
            self.assertIn(identity_claim, data)
            self.assertEqual(data[identity_claim], identity)
            self.assertEqual(data['type'], 'refresh')
            self.assertEqual(data['iat'], data['nbf'])
            now_ts = calendar.timegm(datetime.utcnow().utctimetuple())
            exp_seconds = data['exp'] - now_ts
            self.assertLessEqual(exp_seconds, 60 * 5)
            self.assertGreater(exp_seconds, 60 * 4)

    def test_decode_jwt(self):
        identity_claim = 'sub'
        # Test decoding a valid access token
        with self.app.test_request_context():
            now = datetime.utcnow()
            now_ts = calendar.timegm(now.utctimetuple())
            token_data = {
                'exp': now + timedelta(minutes=5),
                'iat': now,
                'nbf': now,
                'jti': 'banana',
                identity_claim: 'banana',
                'fresh': True,
                'type': 'access',
                'user_claims': {'foo': 'bar'},
            }
            encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
            data = decode_jwt(encoded_token, 'secret', 'HS256',
                              csrf=False, identity_claim=identity_claim)
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn(identity_claim, data)
            self.assertIn('fresh', data)
            self.assertIn('type', data)
            self.assertIn('user_claims', data)
            self.assertEqual(data['exp'], now_ts + (5 * 60))
            self.assertEqual(data['iat'], now_ts)
            self.assertEqual(data['nbf'], now_ts)
            self.assertEqual(data['jti'], 'banana')
            self.assertEqual(data[identity_claim], 'banana')
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
                identity_claim: 'banana',
                'type': 'refresh',
            }
            encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
            data = decode_jwt(encoded_token, 'secret', 'HS256',
                              csrf=False, identity_claim=identity_claim)
            self.assertIn('exp', data)
            self.assertIn('iat', data)
            self.assertIn('nbf', data)
            self.assertIn('jti', data)
            self.assertIn(identity_claim, data)
            self.assertIn('type', data)
            self.assertEqual(data['exp'], now_ts + (5 * 60))
            self.assertEqual(data['iat'], now_ts)
            self.assertEqual(data['nbf'], now_ts)
            self.assertEqual(data['jti'], 'banana')
            self.assertEqual(data[identity_claim], 'banana')
            self.assertEqual(data['type'], 'refresh')

    def test_decode_access_token__no_user_claims(self):
        '''
        Test decoding a valid access token without `user_claims`.
        '''
        identity_claim = 'sub'
        with self.app.test_request_context():
            now = datetime.utcnow()
            token_data = {
                'exp': now + timedelta(minutes=5),
                'iat': now,
                'nbf': now,
                'jti': 'banana',
                identity_claim: 'banana',
                'fresh': True,
                'type': 'access',
            }
            encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
            data = decode_jwt(encoded_token, 'secret', 'HS256',
                              csrf=False, identity_claim=identity_claim)

            self.assertIn('user_claims', data)
            self.assertEqual(data['user_claims'], {})

    def test_decode_invalid_jwt(self):
        with self.app.test_request_context():
            identity_claim = 'identity'
            # Verify underlying pyjwt expires verification works
            with self.assertRaises(jwt.ExpiredSignatureError):
                token_data = {
                    'exp': datetime.utcnow() - timedelta(minutes=5),
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                decode_jwt(encoded_token, 'secret', 'HS256',
                           csrf=False, identity_claim=identity_claim)

            # Missing jti
            with self.assertRaises(JWTDecodeError):

                token_data = {
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    identity_claim: 'banana',
                    'type': 'refresh'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                decode_jwt(encoded_token, 'secret', 'HS256',
                           csrf=False, identity_claim=identity_claim)

            # Missing identity
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'refresh'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                decode_jwt(encoded_token, 'secret', 'HS256',
                           csrf=False, identity_claim=identity_claim)

            # Non-matching identity claim
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    identity_claim: 'banana',
                    'type': 'refresh'
                }
                other_identity_claim = 'sub'
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                self.assertNotEqual(identity_claim, other_identity_claim)
                decode_jwt(encoded_token, 'secret', 'HS256',
                           csrf=False, identity_claim=other_identity_claim)

            # Missing type
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    identity_claim: 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                decode_jwt(encoded_token, 'secret', 'HS256',
                           csrf=False, identity_claim=identity_claim)

            # Missing fresh in access token
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    identity_claim: 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'access',
                    'user_claims': {}
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                decode_jwt(encoded_token, 'secret', 'HS256',
                           csrf=False, identity_claim=identity_claim)

            # Bad token type
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    identity_claim: 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'banana',
                    'fresh': True,
                    'user_claims': 'banana'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                decode_jwt(encoded_token, 'secret', 'HS256',
                           csrf=False, identity_claim=identity_claim)

            # Missing csrf in csrf enabled token
            with self.assertRaises(JWTDecodeError):
                token_data = {
                    'jti': 'banana',
                    identity_claim: 'banana',
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'type': 'access',
                    'fresh': True,
                    'user_claims': 'banana'
                }
                encoded_token = jwt.encode(token_data, 'secret', 'HS256').decode('utf-8')
                decode_jwt(encoded_token, 'secret', 'HS256', csrf=True,
                           identity_claim=identity_claim)

    def test_create_jwt_with_object(self):
        # Complex object to test building a JWT from. Normally if you are using
        # this functionality, this is something that would be retrieved from
        # disk somewhere (think sqlalchemy)
        class TestUser:
            def __init__(self, username, roles):
                self.username = username
                self.roles = roles

        # Setup the flask stuff
        app = Flask(__name__)
        app.secret_key = 'super=secret'
        app.config['JWT_ALGORITHM'] = 'HS256'
        jwt = JWTManager(app)

        @jwt.user_claims_loader
        def custom_claims(user):
            return {
                'roles': user.roles
            }

        @jwt.user_identity_loader
        def user_identity_lookup(user):
            return user.username

        # Create the token using the complex object
        with app.test_request_context():
            identity_claim = 'sub'
            app.config['JWT_IDENTITY_CLAIM'] = identity_claim
            user = TestUser(username='foo', roles=['bar', 'baz'])
            access_token = create_access_token(identity=user)
            refresh_token = create_refresh_token(identity=user)

            # Decode the tokens and make sure the values are set properly
            access_token_data = decode_jwt(access_token, app.secret_key,
                                           app.config['JWT_ALGORITHM'], csrf=False,
                                           identity_claim=identity_claim)
            refresh_token_data = decode_jwt(refresh_token, app.secret_key,
                                            app.config['JWT_ALGORITHM'], csrf=False,
                                            identity_claim=identity_claim)
            self.assertEqual(access_token_data[identity_claim], 'foo')
            self.assertEqual(access_token_data['user_claims']['roles'], ['bar', 'baz'])
            self.assertEqual(refresh_token_data[identity_claim], 'foo')
