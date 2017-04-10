import unittest
import warnings
from datetime import timedelta

import simplekv.memory
from flask import Flask

from flask_jwt_extended.config import config
from flask_jwt_extended import JWTManager


class TestEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        JWTManager(self.app)

    def test_default_configs(self):
        with self.app.test_request_context():
            self.assertEqual(config.token_location, ['headers'])
            self.assertEqual(config.jwt_in_cookies, False)
            self.assertEqual(config.jwt_in_headers, True)
            self.assertEqual(config.header_name, 'Authorization')
            self.assertEqual(config.header_type, 'Bearer')

            self.assertEqual(config.access_cookie_name, 'access_token_cookie')
            self.assertEqual(config.refresh_cookie_name, 'refresh_token_cookie')
            self.assertEqual(config.access_cookie_path, '/')
            self.assertEqual(config.refresh_cookie_path, '/')
            self.assertEqual(config.cookie_secure, False)
            self.assertEqual(config.session_cookie, True)

            self.assertEqual(config.csrf_protect, False)
            self.assertEqual(config.csrf_request_methods, ['POST', 'PUT', 'PATCH', 'DELETE'])
            self.assertEqual(config.csrf_in_cookies, True)
            self.assertEqual(config.access_csrf_cookie_name, 'csrf_access_token')
            self.assertEqual(config.refresh_csrf_cookie_name, 'csrf_refresh_token')
            self.assertEqual(config.access_csrf_cookie_path, '/')
            self.assertEqual(config.refresh_csrf_cookie_path, '/')
            self.assertEqual(config.access_csrf_header_name, 'X-CSRF-TOKEN')
            self.assertEqual(config.refresh_csrf_header_name, 'X-CSRF-TOKEN')

            self.assertEqual(config.access_expires, timedelta(minutes=15))
            self.assertEqual(config.refresh_expires, timedelta(days=30))
            self.assertEqual(config.algorithm, 'HS256')
            self.assertEqual(config.blacklist_enabled, False)
            self.assertEqual(config.blacklist_checks, 'refresh')
            self.assertEqual(config.blacklist_access_tokens, False)

            self.assertEqual(config.secret_key, self.app.secret_key)
            self.assertEqual(config.cookie_max_age, None)

            with self.assertRaises(RuntimeError):
                config.blacklist_store

    def test_override_configs(self):
        sample_store = simplekv.memory.DictStore()

        self.app.config['JWT_TOKEN_LOCATION'] = ['cookies']
        self.app.config['JWT_HEADER_NAME'] = 'TestHeader'
        self.app.config['JWT_HEADER_TYPE'] = 'TestType'

        self.app.config['JWT_ACCESS_COOKIE_NAME'] = 'new_access_cookie'
        self.app.config['JWT_REFRESH_COOKIE_NAME'] = 'new_refresh_cookie'
        self.app.config['JWT_ACCESS_COOKIE_PATH'] = '/access/path'
        self.app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh/path'
        self.app.config['JWT_COOKIE_SECURE'] = True
        self.app.config['JWT_SESSION_COOKIE'] = False

        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        self.app.config['JWT_CSRF_METHODS'] = ['GET']
        self.app.config['JWT_CSRF_IN_COOKIES'] = False
        self.app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'access_csrf_cookie'
        self.app.config['JWT_REFRESH_CSRF_COOKIE_NAME'] = 'refresh_csrf_cookie'
        self.app.config['JWT_ACCESS_CSRF_COOKIE_PATH'] = '/csrf/access/path'
        self.app.config['JWT_REFRESH_CSRF_COOKIE_PATH'] = '/csrf/refresh/path'
        self.app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = 'X-ACCESS-CSRF'
        self.app.config['JWT_REFRESH_CSRF_HEADER_NAME'] = 'X-REFRESH-CSRF'

        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=5)
        self.app.config['JWT_ALGORITHM'] = 'HS512'

        self.app.config['JWT_BLACKLIST_ENABLED'] = True
        self.app.config['JWT_BLACKLIST_STORE'] = sample_store
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'all'

        self.app.secret_key = 'banana'

        with self.app.test_request_context():
            self.assertEqual(config.token_location, ['cookies'])
            self.assertEqual(config.jwt_in_cookies, True)
            self.assertEqual(config.jwt_in_headers, False)
            self.assertEqual(config.header_name, 'TestHeader')
            self.assertEqual(config.header_type, 'TestType')

            self.assertEqual(config.access_cookie_name, 'new_access_cookie')
            self.assertEqual(config.refresh_cookie_name, 'new_refresh_cookie')
            self.assertEqual(config.access_cookie_path, '/access/path')
            self.assertEqual(config.refresh_cookie_path, '/refresh/path')
            self.assertEqual(config.cookie_secure, True)
            self.assertEqual(config.session_cookie, False)

            self.assertEqual(config.csrf_protect, True)
            self.assertEqual(config.csrf_request_methods, ['GET'])
            self.assertEqual(config.csrf_in_cookies, False)
            self.assertEqual(config.access_csrf_cookie_name, 'access_csrf_cookie')
            self.assertEqual(config.refresh_csrf_cookie_name, 'refresh_csrf_cookie')
            self.assertEqual(config.access_csrf_cookie_path, '/csrf/access/path')
            self.assertEqual(config.refresh_csrf_cookie_path, '/csrf/refresh/path')
            self.assertEqual(config.access_csrf_header_name, 'X-ACCESS-CSRF')
            self.assertEqual(config.refresh_csrf_header_name, 'X-REFRESH-CSRF')

            self.assertEqual(config.access_expires, timedelta(minutes=5))
            self.assertEqual(config.refresh_expires, timedelta(days=5))
            self.assertEqual(config.algorithm, 'HS512')

            self.assertEqual(config.blacklist_enabled, True)
            self.assertEqual(config.blacklist_store, sample_store)
            self.assertEqual(config.blacklist_checks, 'all')
            self.assertEqual(config.blacklist_access_tokens, True)

            self.assertEqual(config.secret_key, 'banana')
            self.assertEqual(config.cookie_max_age, 2147483647)

    def test_invalid_config_options(self):
        with self.app.test_request_context():
            self.app.config['JWT_TOKEN_LOCATION'] = 'banana'
            with self.assertRaises(RuntimeError):
                config.token_location

            self.app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies', 'banana']
            with self.assertRaises(RuntimeError):
                config.token_location

            self.app.config['JWT_HEADER_NAME'] = ''
            with self.app.test_request_context():
                with self.assertRaises(RuntimeError):
                    config.header_name

            self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 'banana'
            with self.assertRaises(RuntimeError):
                config.access_expires

            self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 'banana'
            with self.assertRaises(RuntimeError):
                config.refresh_expires

            self.app.config['JWT_BLACKLIST_STORE'] = {}
            with self.assertRaises(RuntimeError):
                config.blacklist_store

            self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'banana'
            with self.assertRaises(RuntimeError):
                config.blacklist_checks

            self.app.secret_key = None
            with self.assertRaises(RuntimeError):
                config.secret_key

            self.app.secret_key = ''
            with self.assertRaises(RuntimeError):
                config.secret_key

    def test_depreciated_options(self):
        self.app.config['JWT_CSRF_HEADER_NAME'] = 'Auth'

        # Cause all warnings to always be triggered.
        warnings.simplefilter("always")

        # Verify our warnings are thrown
        with self.app.test_request_context():
            with warnings.catch_warnings(record=True) as w:
                self.assertEqual(config.access_csrf_header_name, 'Auth')
                self.assertEqual(config.refresh_csrf_header_name, 'Auth')
                self.assertEqual(len(w), 2)
                self.assertEqual(w[0].category, DeprecationWarning)
                self.assertEqual(w[1].category, DeprecationWarning)

    def test_special_config_options(self):
        with self.app.test_request_context():
            # Test changing strings to lists for JWT_TOKEN_LOCATIONS
            self.app.config['JWT_TOKEN_LOCATION'] = 'headers'
            self.assertEqual(config.token_location, ['headers'])
            self.app.config['JWT_TOKEN_LOCATION'] = ['headers']
            self.assertEqual(config.token_location, ['headers'])
            self.app.config['JWT_TOKEN_LOCATION'] = 'cookies'
            self.assertEqual(config.token_location, ['cookies'])
            self.app.config['JWT_TOKEN_LOCATION'] = ['cookies']
            self.assertEqual(config.token_location, ['cookies'])
            self.app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
            self.assertEqual(config.token_location, ['cookies', 'headers'])

            # Test csrf protect options
            self.app.config['JWT_TOKEN_LOCATION'] = ['headers']
            self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True
            self.assertEqual(config.csrf_protect, False)
            self.app.config['JWT_TOKEN_LOCATION'] = ['cookies']
            self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True
            self.assertEqual(config.csrf_protect, True)
            self.app.config['JWT_TOKEN_LOCATION'] = ['cookies']
            self.app.config['JWT_COOKIE_CSRF_PROTECT'] = False
            self.assertEqual(config.csrf_protect, False)
