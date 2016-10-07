import datetime
from flask import current_app

# TODO move this to the docs
# blacklist storage options (simplekv). If using a storage option that supports
# the simplekv.TimeToLiveMixin (example: redis, memcached), the TTL will be
# automatically set to 15 minutes after the token expires (to account for
# clock drift between different jwt providers/consumers).
#
# See: http://pythonhosted.org/simplekv/index.html#simplekv.TimeToLiveMixin


# Where to look for the JWT. Available options are cookie and header
REQUEST_JWT_LOCATION = 'header'

# Options for where to get the JWT if using a header approach
HEADER_NAME = 'Authorization'
HEADER_TYPE = 'Bearer'

# Options for where to get and handling JWTs if using a cookie approach
COOKIE_ACCESS_TOKEN_NAME = 'access_token'
COOKIE_REFRESH_TOKEN_NAME = 'refresh_token'
COOKIE_CSRF_DOUBLE_SUBMIT = False
COOKIE_XSRF_ACCESS_NAME = 'xsrf_access_token'
COOKIE_XSRF_REFRESH_NAME = 'xsrf_refresh_token'

# How long an a token will live before they expire.
ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=30)

# What algorithm to use to sign the token. See here for a list of options:
# https://github.com/jpadilla/pyjwt/blob/master/jwt/api_jwt.py (note that
# public private key is not yet supported)
ALGORITHM = 'HS256'

# Options for blacklisting/revoking tokens
BLACKLIST_ENABLED = False
BLACKLIST_STORE = None
BLACKLIST_TOKEN_CHECKS = 'refresh'  # valid options are 'all', and 'refresh'


def get_jwt_header_name():
    name = current_app.config.get('JWT_HEADER_NAME', HEADER_NAME)
    if not name:
        raise RuntimeError("JWT_HEADER_NAME must be set")
    return name


def get_jwt_header_type():
    return current_app.config.get('JWT_HEADER_TYPE', HEADER_TYPE)


def get_access_expires():
    delta = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', ACCESS_TOKEN_EXPIRES)
    if not isinstance(delta, datetime.timedelta):
        raise RuntimeError('JWT_ACCESS_TOKEN_EXPIRES must be a datetime.timedelta')
    return delta


def get_refresh_expires():
    delta = current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES', REFRESH_TOKEN_EXPIRES)
    if not isinstance(delta, datetime.timedelta):
        raise RuntimeError('JWT_REFRESH_TOKEN_EXPIRES must be a datetime.timedelta')
    return delta


def get_algorithm():
    return current_app.config.get('JWT_ALGORITHM', ALGORITHM)


def get_blacklist_enabled():
    return current_app.config.get('JWT_BLACKLIST_ENABLED', BLACKLIST_ENABLED)


def get_blacklist_store():
    return current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)


def get_blacklist_checks():
    return current_app.config.get('JWT_BLACKLIST_TOKEN_CHECKS', BLACKLIST_TOKEN_CHECKS)
