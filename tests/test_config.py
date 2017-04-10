import unittest
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
        self.client = self.app.test_client()

    def test_default_configs(self):
        with self.app.test_request_context():
            self.assertEqual(config.token_location, ['headers'])
            self.assertEqual(config.access_header_name, 'Authorization')
            self.assertEqual(config.refresh_header_name, 'Authorization')
            self.assertEqual(config.header_type, 'Bearer')

            self.assertEqual(config.cookie_secure, False)
            self.assertEqual(config.access_cookie_name, 'access_token_cookie')
            self.assertEqual(config.refresh_cookie_name, 'refresh_token_cookie')
            self.assertEqual(config.access_cookie_path, '/')
            self.assertEqual(config.refresh_cookie_path, '/')
            self.assertEqual(config.session_cookie, True)
            self.assertEqual(config.csrf_protect, False)
            self.assertEqual(config.access_csrf_cookie_name, 'csrf_access_token')
            self.assertEqual(config.refresh_csrf_cookie_name, 'csrf_refresh_token')
            self.assertEqual(config.access_csrf_header_name, 'X-CSRF-TOKEN')
            self.assertEqual(config.refresh_csrf_header_name, 'X-CSRF-TOKEN')

            self.assertEqual(config.access_expires, timedelta(minutes=15))
            self.assertEqual(config.refresh_expires, timedelta(days=30))
            self.assertEqual(config.algorithm, 'HS256')
            self.assertEqual(config.blacklist_enabled, False)
            self.assertEqual(config.blacklist_checks, 'refresh')

            with self.assertRaises(RuntimeError):
                self.assertEqual(config.blacklist_store, None)

    def test_override_configs(self):
        self.app.config['JWT_TOKEN_LOCATION'] = 'cookies'
        self.app.config['JWT_ACCESS_HEADER_NAME'] = 'Auth'
        self.app.config['JWT_REFRESH_HEADER_NAME'] = 'Auth'
        self.app.config['JWT_HEADER_TYPE'] = 'JWT'

        self.app.config['JWT_COOKIE_SECURE'] = True
        self.app.config['JWT_ACCESS_COOKIE_NAME'] = 'banana1'
        self.app.config['JWT_REFRESH_COOKIE_NAME'] = 'banana2'
        self.app.config['JWT_ACCESS_COOKIE_PATH'] = '/banana/'
        self.app.config['JWT_REFRESH_COOKIE_PATH'] = '/banana2/'
        self.app.config['JWT_SESSION_COOKIE'] = False
        self.app.config['JWT_COOKIE_CSRF_PROTECT'] = True
        self.app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'banana1a'
        self.app.config['JWT_REFRESH_CSRF_COOKIE_NAME'] = 'banana2a'
        self.app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = 'bananaaaa'
        self.app.config['JWT_REFRESH_CSRF_HEADER_NAME'] = 'bananaaaa2'

        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
        self.app.config['JWT_ALGORITHM'] = 'HS512'
        self.app.config['JWT_BLACKLIST_ENABLED'] = True
        self.app.config['JWT_BLACKLIST_STORE'] = simplekv.memory.DictStore()
        self.app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'all'

        with self.app.test_request_context():
            self.assertEqual(config.token_location, ['cookies'])
            self.assertEqual(config.access_header_name, 'Auth')
            self.assertEqual(config.refresh_header_name, 'Auth')
            self.assertEqual(config.header_type, 'JWT')

            self.assertEqual(config.cookie_secure, True)
            self.assertEqual(config.access_cookie_name, 'banana1')
            self.assertEqual(config.refresh_cookie_name, 'banana2')
            self.assertEqual(config.access_cookie_path, '/banana/')
            self.assertEqual(config.refresh_cookie_path, '/banana2/')
            self.assertEqual(config.session_cookie, False)
            self.assertEqual(config.csrf_protect, True)
            self.assertEqual(config.access_csrf_cookie_name, 'banana1a')
            self.assertEqual(config.refresh_csrf_cookie_name, 'banana2a')
            self.assertEqual(config.access_csrf_header_name, 'bananaaaa')
            self.assertEqual(config.refresh_csrf_header_name, 'bananaaaa2')

            self.assertEqual(config.access_expires, timedelta(minutes=5))
            self.assertEqual(config.refresh_expires, timedelta(days=7))
            self.assertEqual(config.algorithm, 'HS512')
            self.assertEqual(config.blacklist_enabled, True)
            self.assertEqual(config.blacklist_checks, 'all')

        self.app.config['JWT_TOKEN_LOCATION'] = 'banana'
        self.app.config['JWT_ACCESS_HEADER_NAME'] = ''
        self.app.config['JWT_REFRESH_HEADER_NAME'] = ''
        self.app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 'banana'
        self.app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 'banana'

        with self.app.test_request_context():
            with self.assertRaises(RuntimeError):
                config.access_header_name
            with self.assertRaises(RuntimeError):
                config.refresh_header_name
            with self.assertRaises(RuntimeError):
                config.access_expires
            with self.assertRaises(RuntimeError):
                config.refresh_expires
            with self.assertRaises(RuntimeError):
                config.token_location
