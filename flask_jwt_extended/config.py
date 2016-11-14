import datetime
from flask import current_app


# TODO support for cookies and headers at the same time. This could be useful
#      for using cookies in a web browser (more secure), and headers in a mobile
#      app (don't have to worry about csrf/xss there, and headers are easier to
#      manage in that environment)

# Where to look for the JWT. Available options are cookies or headers
TOKEN_LOCATION = 'headers'

# Options for JWTs when the TOKEN_LOCATION is headers
HEADER_NAME = 'Authorization'
HEADER_TYPE = 'Bearer'

# Option for JWTs when the TOKEN_LOCATION is cookies
COOKIE_SECURE = False
ACCESS_COOKIE_NAME = 'access_token_cookie'
REFRESH_COOKIE_NAME = 'refresh_token_cookie'
ACCESS_COOKIE_PATH = None
REFRESH_COOKIE_PATH = None

# Options for using double submit for verifying CSRF tokens
COOKIE_CSRF_PROTECT = True
ACCESS_CSRF_COOKIE_NAME = 'csrf_access_token'
REFRESH_CSRF_COOKIE_NAME = 'csrf_refresh_token'
CSRF_HEADER_NAME = 'X-CSRF-TOKEN'

# How long an a token will live before they expire.
ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES = datetime.timedelta(days=30)

# What algorithm to use to sign the token. See here for a list of options:
# https://github.com/jpadilla/pyjwt/blob/master/jwt/api_jwt.py (note that
# public private key is not yet supported)
ALGORITHM = 'HS256'

# Options for blacklisting/revoking tokens
BLACKLIST_ENABLED = False
BLACKLIST_STORE = None  # simplekv object: https://pypi.python.org/pypi/simplekv/
BLACKLIST_TOKEN_CHECKS = 'refresh'  # valid options are 'all', and 'refresh'


def get_token_location():
    location = current_app.config.get('JWT_TOKEN_LOCATION', TOKEN_LOCATION)
    if location not in ['headers', 'cookies']:
        raise RuntimeError('JWT_LOCATION_LOCATION must be "headers" or "cookies"')
    return location


def get_jwt_header_name():
    name = current_app.config.get('JWT_HEADER_NAME', HEADER_NAME)
    if not name:
        raise RuntimeError("JWT_HEADER_NAME must be set")
    return name


def get_cookie_secure():
    return current_app.config.get('JWT_COOKIE_SECURE', COOKIE_SECURE)


def get_access_cookie_name():
    return current_app.config.get('JWT_ACCESS_COOKIE_NAME', ACCESS_COOKIE_NAME)


def get_refresh_cookie_name():
    return current_app.config.get('JWT_REFRESH_COOKIE_NAME', REFRESH_COOKIE_NAME)


def get_access_cookie_path():
    return current_app.config.get('JWT_ACCESS_COOKIE_PATH', ACCESS_COOKIE_PATH)


def get_refresh_cookie_path():
    return current_app.config.get('JWT_REFRESH_COOKIE_PATH', REFRESH_COOKIE_PATH)


def get_cookie_csrf_protect():
    return current_app.config.get('JWT_COOKIE_CSRF_PROTECT', COOKIE_CSRF_PROTECT)


def get_access_csrf_cookie_name():
    return current_app.config.get('JWT_ACCESS_CSRF_COOKIE_NAME', ACCESS_CSRF_COOKIE_NAME)


def get_refresh_csrf_cookie_name():
    return current_app.config.get('JWT_REFRESH_CSRF_COOKIE_NAME', REFRESH_CSRF_COOKIE_NAME)


def get_csrf_header_name():
    return current_app.config.get('JWT_CSRF_HEADER_NAME', CSRF_HEADER_NAME)


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
