import datetime

# How long an access token will live before it expires.
ACCESS_EXPIRES = datetime.timedelta(minutes=15)

# How long the refresh token will live before it expires
REFRESH_EXPIRES = datetime.timedelta(days=30)

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

# blacklist check requests. Possible values are all, refresh, and None
# TODO when accessing this value in app.config, make sure it is one of the expected values
BLACKLIST_TOKEN_CHECKS = None
