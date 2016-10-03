import datetime
from flask import current_app

# Defaults

# Authorize header type, what we are expecting to see in the auth header
AUTH_HEADER = 'Bearer'

# How long an access token will live before it expires.
ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=15)

# How long the refresh token will live before it expires
REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=30)

# What algorithm to use to sign the token. See here for a list of options:
# https://github.com/jpadilla/pyjwt/blob/master/jwt/api_jwt.py
ALGORITHM = 'HS256'

# Blacklist enabled
BLACKLIST_ENABLED = False

# blacklist storage options (simplekv). If using a storage option that supports
# the simplekv.TimeToLiveMixin (example: redis, memcached), the TTL will be
# automatically set to 15 minutes after the token expires (to account for
# clock drift between different jwt providers/consumers).
#
# See: http://pythonhosted.org/simplekv/index.html#simplekv.TimeToLiveMixin
BLACKLIST_STORE = None

# blacklist check requests. Possible values are all and refresh
BLACKLIST_TOKEN_CHECKS = 'refresh'


def get_auth_header():
    return current_app.config.get('JWT_AUTH_HEADER', AUTH_HEADER)


def get_access_expires():
    return current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', ACCESS_TOKEN_EXPIRES)


def get_refresh_expires():
    return current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES', REFRESH_TOKEN_EXPIRES)


def get_algorithm():
    return current_app.config.get('JWT_ALGORITHM', ALGORITHM)


def get_blacklist_enabled():
    return current_app.config.get('JWT_BLACKLIST_ENABLED', BLACKLIST_ENABLED)


def get_blacklist_store():
    return current_app.config.get('JWT_BLACKLIST_STORE', BLACKLIST_STORE)


def get_blacklist_checks():
    return current_app.config.get('JWT_BLACKLIST_TOKEN_CHECKS', BLACKLIST_TOKEN_CHECKS)
