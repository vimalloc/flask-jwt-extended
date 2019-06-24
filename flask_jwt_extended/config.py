import datetime
from warnings import warn
from six import raise_from

# In Python 2.7 collections.abc is a part of the collections module.
try:
    from collections.abc import Sequence, Set
except ImportError:  # pragma: no cover
    from collections import Sequence, Set

from flask import current_app

# Older versions of pyjwt do not have the requires_cryptography set. Also,
# older versions will not be adding new algorithms to them, so I can hard code
# the default version here and be safe. If there is a newer algorithm someone
# wants to use, they will need newer versions of pyjwt and it will be included
# in their requires_cryptography set, and if they attempt to use it in older
# versions of pyjwt, it will kick it out as an unrecognized algorithm.
try:
    from jwt.algorithms import requires_cryptography
except ImportError:  # pragma: no cover
    requires_cryptography = {'RS256', 'RS384', 'RS512', 'ES256', 'ES384',
                             'ES521', 'ES512', 'PS256', 'PS384', 'PS512'}


class _Config(object):
    """
    Helper object for accessing and verifying options in this extension. This
    is meant for internal use of the application; modifying config options
    should be done with flasks ```app.config```.

    Default values for the configuration options are set in the jwt_manager
    object. All of these values are read only. This is simply a loose wrapper
    with some helper functionality for flasks `app.config`.
    """

    @property
    def is_asymmetric(self):
        return self.algorithm in requires_cryptography

    @property
    def encode_key(self):
        return self._private_key if self.is_asymmetric else self._secret_key

    @property
    def decode_key(self):
        return self._public_key if self.is_asymmetric else self._secret_key

    @property
    def token_location(self):
        locations = current_app.config['JWT_TOKEN_LOCATION']
        if isinstance(locations, str):
            locations = (locations,)
        elif not isinstance(locations, (Sequence, Set)):
            raise RuntimeError('JWT_TOKEN_LOCATION must be a sequence or a set')
        elif not locations:
            raise RuntimeError('JWT_TOKEN_LOCATION must contain at least one '
                               'of "headers", "cookies", "query_string", or "json"')
        for location in locations:
            if location not in ('headers', 'cookies', 'query_string', 'json'):
                raise RuntimeError('JWT_TOKEN_LOCATION can only contain '
                                   '"headers", "cookies", "query_string", or "json"')
        return locations

    @property
    def jwt_in_cookies(self):
        return 'cookies' in self.token_location

    @property
    def jwt_in_headers(self):
        return 'headers' in self.token_location

    @property
    def jwt_in_query_string(self):
        return 'query_string' in self.token_location

    @property
    def jwt_in_json(self):
        return 'json' in self.token_location

    @property
    def header_name(self):
        name = current_app.config['JWT_HEADER_NAME']
        if not name:
            raise RuntimeError("JWT_ACCESS_HEADER_NAME cannot be empty")
        return name

    @property
    def header_type(self):
        return current_app.config['JWT_HEADER_TYPE']

    @property
    def query_string_name(self):
        return current_app.config['JWT_QUERY_STRING_NAME']

    @property
    def access_cookie_name(self):
        return current_app.config['JWT_ACCESS_COOKIE_NAME']

    @property
    def refresh_cookie_name(self):
        return current_app.config['JWT_REFRESH_COOKIE_NAME']

    @property
    def access_cookie_path(self):
        return current_app.config['JWT_ACCESS_COOKIE_PATH']

    @property
    def refresh_cookie_path(self):
        return current_app.config['JWT_REFRESH_COOKIE_PATH']

    @property
    def cookie_secure(self):
        return current_app.config['JWT_COOKIE_SECURE']

    @property
    def cookie_domain(self):
        return current_app.config['JWT_COOKIE_DOMAIN']

    @property
    def session_cookie(self):
        return current_app.config['JWT_SESSION_COOKIE']

    @property
    def cookie_samesite(self):
        return current_app.config['JWT_COOKIE_SAMESITE']

    @property
    def json_key(self):
        return current_app.config['JWT_JSON_KEY']

    @property
    def refresh_json_key(self):
        return current_app.config['JWT_REFRESH_JSON_KEY']

    @property
    def csrf_protect(self):
        return self.jwt_in_cookies and current_app.config['JWT_COOKIE_CSRF_PROTECT']

    @property
    def csrf_request_methods(self):
        return current_app.config['JWT_CSRF_METHODS']

    @property
    def csrf_in_cookies(self):
        return current_app.config['JWT_CSRF_IN_COOKIES']

    @property
    def access_csrf_cookie_name(self):
        return current_app.config['JWT_ACCESS_CSRF_COOKIE_NAME']

    @property
    def refresh_csrf_cookie_name(self):
        return current_app.config['JWT_REFRESH_CSRF_COOKIE_NAME']

    @property
    def access_csrf_cookie_path(self):
        return current_app.config['JWT_ACCESS_CSRF_COOKIE_PATH']

    @property
    def refresh_csrf_cookie_path(self):
        return current_app.config['JWT_REFRESH_CSRF_COOKIE_PATH']

    @staticmethod
    def _get_depreciated_csrf_header_name():
        # This used to be the same option for access and refresh header names.
        # This gives users a warning if they are still using the old behavior
        old_name = current_app.config.get('JWT_CSRF_HEADER_NAME', None)
        if old_name:
            msg = (
                "JWT_CSRF_HEADER_NAME is depreciated. Use JWT_ACCESS_CSRF_HEADER_NAME "
                "or JWT_REFRESH_CSRF_HEADER_NAME instead"
            )
            warn(msg, DeprecationWarning)
        return old_name

    @property
    def access_csrf_header_name(self):
        return self._get_depreciated_csrf_header_name() or \
               current_app.config['JWT_ACCESS_CSRF_HEADER_NAME']

    @property
    def refresh_csrf_header_name(self):
        return self._get_depreciated_csrf_header_name() or \
               current_app.config['JWT_REFRESH_CSRF_HEADER_NAME']

    @property
    def access_expires(self):
        delta = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        if type(delta) is int:
            delta = datetime.timedelta(seconds=delta)
        if delta is not False:
            try:
                delta + datetime.datetime.now()
            except TypeError as e:
                err = (
                    "must be able to add JWT_ACCESS_TOKEN_EXPIRES to datetime.datetime"
                )
                raise_from(RuntimeError(err), e)
        return delta

    @property
    def refresh_expires(self):
        delta = current_app.config['JWT_REFRESH_TOKEN_EXPIRES']
        if type(delta) is int:
            delta = datetime.timedelta(seconds=delta)
        if delta is not False:
            try:
                delta + datetime.datetime.now()
            except TypeError as e:
                err = (
                    "must be able to add JWT_REFRESH_TOKEN_EXPIRES to datetime.datetime"
                )
                raise_from(RuntimeError(err), e)
        return delta

    @property
    def algorithm(self):
        return current_app.config['JWT_ALGORITHM']

    @property
    def decode_algorithms(self):
        algorithms = current_app.config['JWT_DECODE_ALGORITHMS']
        if not algorithms:
            return [self.algorithm]
        if self.algorithm not in algorithms:
            algorithms.append(self.algorithm)
        return algorithms

    @property
    def blacklist_enabled(self):
        return current_app.config['JWT_BLACKLIST_ENABLED']

    @property
    def blacklist_checks(self):
        check_type = current_app.config['JWT_BLACKLIST_TOKEN_CHECKS']
        if isinstance(check_type, str):
            check_type = (check_type,)
        elif not isinstance(check_type, (Sequence, Set)):
            raise RuntimeError('JWT_BLACKLIST_TOKEN_CHECKS must be a sequence or a set')
        for item in check_type:
            if item not in ('access', 'refresh'):
                err = 'JWT_BLACKLIST_TOKEN_CHECKS must be "access" or "refresh"'
                raise RuntimeError(err)
        return check_type

    @property
    def blacklist_access_tokens(self):
        return 'access' in self.blacklist_checks

    @property
    def blacklist_refresh_tokens(self):
        return 'refresh' in self.blacklist_checks

    @property
    def _secret_key(self):
        key = current_app.config['JWT_SECRET_KEY']
        if not key:
            key = current_app.config.get('SECRET_KEY', None)
            if not key:
                raise RuntimeError('JWT_SECRET_KEY or flask SECRET_KEY '
                                   'must be set when using symmetric '
                                   'algorithm "{}"'.format(self.algorithm))
        return key

    @property
    def _public_key(self):
        key = current_app.config['JWT_PUBLIC_KEY']
        if not key:
            raise RuntimeError('JWT_PUBLIC_KEY must be set to use '
                               'asymmetric cryptography algorithm '
                               '"{}"'.format(self.algorithm))
        return key

    @property
    def _private_key(self):
        key = current_app.config['JWT_PRIVATE_KEY']
        if not key:
            raise RuntimeError('JWT_PRIVATE_KEY must be set to use '
                               'asymmetric cryptography algorithm '
                               '"{}"'.format(self.algorithm))
        return key

    @property
    def cookie_max_age(self):
        # Returns the appropiate value for max_age for flask set_cookies. If
        # session cookie is true, return None, otherwise return a number of
        # seconds 1 year in the future
        return None if self.session_cookie else 31540000  # 1 year

    @property
    def identity_claim_key(self):
        return current_app.config['JWT_IDENTITY_CLAIM']

    @property
    def user_claims_key(self):
        return current_app.config['JWT_USER_CLAIMS']

    @property
    def user_claims_in_refresh_token(self):
        return current_app.config['JWT_CLAIMS_IN_REFRESH_TOKEN']

    @property
    def exempt_methods(self):
        return {"OPTIONS"}

    @property
    def error_msg_key(self):
        return current_app.config['JWT_ERROR_MESSAGE_KEY']

    @property
    def json_encoder(self):
        return current_app.json_encoder

    @property
    def audience(self):
        return current_app.config['JWT_DECODE_AUDIENCE']

    @property
    def leeway(self):
        return current_app.config['JWT_DECODE_LEEWAY']


config = _Config()
