import unittest
from datetime import timedelta

import simplekv.memory
from flask import Flask

from flask_jwt_extended.config import get_access_expires, get_refresh_expires, \
    get_algorithm, get_blacklist_enabled, get_blacklist_store, \
    get_blacklist_checks, get_jwt_header_type, get_jwt_header_name, \
    get_token_location, get_cookie_secure, get_access_cookie_name, \
    get_refresh_cookie_name, get_access_cookie_path, get_refresh_cookie_path, \
    get_cookie_csrf_protect, get_access_csrf_cookie_name, \
    get_refresh_csrf_cookie_name, get_csrf_header_name
from flask_jwt_extended import JWTManager



class TestEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'super=secret'
        JWTManager(self.app)
        self.client = self.app.test_client()

    def test_default_configs(self):
        with self.app.test_request_context():
            self.assertEqual(get_token_location(), 'headers')
            self.assertEqual(get_jwt_header_name(), 'Authorization')
            self.assertEqual(get_jwt_header_type(), 'Bearer')

            self.assertEqual(get_cookie_secure(), False)
            self.assertEqual(get_access_cookie_name(), 'access_token_cookie')
            self.assertEqual(get_refresh_cookie_name(), 'refresh_token_cookie')
            self.assertEqual(get_access_cookie_path(), None)
            self.assertEqual(get_refresh_cookie_path(), None)
            self.assertEqual(get_cookie_csrf_protect(), True)
            self.assertEqual(get_access_csrf_cookie_name(), 'csrf_access_token')
            self.assertEqual(get_refresh_csrf_cookie_name(), 'csrf_refresh_token')
            self.assertEqual(get_csrf_header_name(), 'X-CSRF-TOKEN')

            self.assertEqual(get_access_expires(), timedelta(minutes=15))
            self.assertEqual(get_refresh_expires(), timedelta(days=30))
            self.assertEqual(get_algorithm(), 'HS256')
            self.assertEqual(get_blacklist_enabled(), False)
            self.assertEqual(get_blacklist_store(), None)
            self.assertEqual(get_blacklist_checks(), 'refresh')

    def test_override_configs(self):
        self.app.config['JWT_TOKEN_LOCATION'] = 'cookies'
        self.app.config['JWT_HEADER_NAME'] = 'Auth'
        self.app.config['JWT_HEADER_TYPE'] = 'JWT'

        self.app.config['JWT_COOKIE_SECURE'] = True
        self.app.config['JWT_ACCESS_COOKIE_NAME'] = 'banana1'
        self.app.config['JWT_REFRESH_COOKIE_NAME'] = 'banana2'
        self.app.config['JWT_ACCESS_COOKIE_PATH'] = '/banana/'
        self.app.config['JWT_REFRESH_COOKIE_PATH'] = '/banana2/'
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = False
        self.app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'banana1a'
        self.app.config['JWT_REFRESH_CSRF_COOKIE_NAME'] = 'banana2a'
        self.app.config['JWT_CSRF_HEADER_NAME'] = 'bananaaaa'

        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
        self.app.config['JWT_ALGORITHM'] = 'HS512'
        self.app.config['JWT_BLACKLIST_ENABLED'] = True
        self.app.config['JWT_BLACKLIST_STORE'] = simplekv.memory.DictStore()
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'all'

        with self.app.test_request_context():
            self.assertEqual(get_token_location(), 'cookies')
            self.assertEqual(get_jwt_header_name(), 'Auth')
            self.assertEqual(get_jwt_header_type(), 'JWT')

            self.assertEqual(get_cookie_secure(), True)
            self.assertEqual(get_access_cookie_name(), 'banana1')
            self.assertEqual(get_refresh_cookie_name(), 'banana2')
            self.assertEqual(get_access_cookie_path(), '/banana/')
            self.assertEqual(get_refresh_cookie_path(), '/banana2/')
            self.assertEqual(get_cookie_csrf_protect(), False)
            self.assertEqual(get_access_csrf_cookie_name(), 'banana1a')
            self.assertEqual(get_refresh_csrf_cookie_name(), 'banana2a')
            self.assertEqual(get_csrf_header_name(), 'bananaaaa')

            self.assertEqual(get_access_expires(), timedelta(minutes=5))
            self.assertEqual(get_refresh_expires(), timedelta(days=7))
            self.assertEqual(get_algorithm(), 'HS512')
            self.assertEqual(get_blacklist_enabled(), True)
            self.assertIsInstance(get_blacklist_store(), simplekv.memory.DictStore)
            self.assertEqual(get_blacklist_checks(), 'all')

        self.app.config['JWT_TOKEN_LOCATION'] = 'banana'
        self.app.config['JWT_HEADER_NAME'] = ''
        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 'banana'
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 'banana'

        self.app.testing = True  # Propagate exceptions
        with self.app.test_request_context():
            with self.assertRaises(RuntimeError):
                get_jwt_header_name()
            with self.assertRaises(RuntimeError):
                get_access_expires()
            with self.assertRaises(RuntimeError):
                get_refresh_expires()
            with self.assertRaises(RuntimeError):
                get_token_location()
