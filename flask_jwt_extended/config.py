# TODO allow these to be overwritten in the app.config

import datetime

# How long an access token will live before it expires
ACCESS_TOKEN_EXPIRE_DELTA = datetime.timedelta(minutes=5)

# How long the refresh token will live before it expires
REFRESH_TOKEN_EXPIRE_DELTA = datetime.timedelta(days=7)

# Blacklist enabled
# blacklist options (simplekv)
# blacklist check requests (all, refresh_token, none)
