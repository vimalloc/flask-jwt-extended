Blacklist and Token Revoking
============================

This extension supports optional token revoking out of the box. This will
allow you to revoke a specific token so that it can no longer access your endpoints.

You will have to choose what tokens you want to check against the blacklist. In
most cases, you will probably want to check both refresh and access tokens, which
is the default behavior. However, if the extra overhead of checking tokens is a
concern you could instead only check the refresh tokens, and set the access
tokens to have a short expires time so any damage a compromised token could
cause is minimal.

Blacklisting works by is providing a callback function to this extension, using the
:meth:`~flask_jwt_extended.JWTManager.token_in_blacklist_loader` decorator.
This method will be called whenever the specified tokens (`access` and/or `refresh`)
are used to access a protected endpoint. If the callback function says that the
token is revoked, we will not allow the call to continue, otherwise we will
allow the call to access the endpoint as normal.


Here is a basic example of this in action.


.. literalinclude:: ../examples/blacklist.py

In production, you will likely want to use either a database or in memory store
(such as redis) to store your tokens. In memory stores are great if you are wanting
to revoke a token when the users logs out, as they are blazing fast. A downside
to using redis is that in the case of a power outage or other such event, it's
possible that you might 'forget' that some tokens have been revoked, depending
on if the redis data was synced to disk.

In contrast to that, databases are great if the data persistance is of the highest
importance (for example, if you have very long lived tokens that other developers
use to access your api), or if you want to add some addition features like showing
users all of their active tokens, and letting them revoke and unrevoke those tokens.

For more in depth examples of these, check out:

- https://github.com/vimalloc/flask-jwt-extended/blob/master/examples/redis_blacklist.py
- https://github.com/vimalloc/flask-jwt-extended/tree/master/examples/database_blacklist
