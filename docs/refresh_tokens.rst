Refresh Tokens
==============

Flask-JWT-Extended supports refresh tokens out of the box. These are long
lived tokens which can be used to create new access tokens once an old access
token has expired. Refresh tokens cannot access a **jwt_requred** protected
endpoint.

.. literalinclude:: ../examples/refresh_tokens.py

By setting the access tokens to a shorter lifetime (see Configuration Options),
and utilizing refresh tokens we can help reduce the damage that can be done if
an access token is stolen. However, we need to take extra care to prevent the
refresh token from being stolen. If an attacker gets his hands on this, he can
keep generating new access tokens and accessing protected endpoints as though
he was that user. We can help combat this by using fresh tokens, discussed in
the next section.
