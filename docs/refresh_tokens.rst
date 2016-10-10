Refresh Tokens
==============

Flask-JWT-Extended supports refresh tokens out of the box. These are longer
lived token which cannot access a jwt_required protected endpoint, but can be
used to create new access tokens once an old access token has expired.

.. literalinclude:: ../examples/refresh_tokens.py

By setting the access tokens to a shorter lifetime (see Configuration Options),
and utilizing fresh tokens for critical views (see Token Freshness next) we can
help reduce the damage done if an access token is stolen.
