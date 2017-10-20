Refresh Tokens
==============

Flask-JWT-Extended supports refresh tokens out of the box. These are long
lived tokens which can be used to create new access tokens once an old access
token has expired. Refresh tokens cannot access an endpoint that is protected
with :func:`~flask_jwt_extended.jwt_required` and access tokens cannot access
and endpoint that is protected with
:func:`~flask_jwt_extended.jwt_refresh_token_required`.

By setting the access tokens to a shorter lifetime (see :ref:`Configuration Options`),
and utilizing refresh tokens we can help reduce the damage that can be done if
an access token is stolen. However, if an attacker gets their hands on the
refresh token, they can keep generating new access tokens and accessing
protected endpoints as though he was that user. We can help combat this by
using the fresh token pattern, discussed in the next section.

Here is an example of using access and refresh tokens:

.. literalinclude:: ../examples/refresh_tokens.py

