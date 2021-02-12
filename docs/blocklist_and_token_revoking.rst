.. _Blocklist and Token Revoking:

JWT Revoking / Blocklist
========================
JWT revoking is a mechanism for preventing an otherwise valid JWT from accessing your
routes while still letting other valid JWTs in. To utilize JWT revoking in this
extension, you must defining a callback function via the
:meth:`~flask_jwt_extended.JWTManager.token_in_blocklist_loader` decorator.
This function is called whenever a valid JWT is used to access a protected route.
The callback will receive the JWT header and JWT payload as arguments, and must
return `True` if the JWT has been revoked.

In production, you will want to use some form of persistent storage (database,
redis, etc) to store your JWTs. It would be bad if your application forgot that
a JWT was revoked if it was restarted. We can provide some general recommendations
on what type of storage engine to use, but ultimately the choice will depend on
your specific application and tech stack.

Redis
~~~~~
If your only requirements are to check if a JWT has been revoked, our recommendation
is to use redis. It is blazing fast, can be configured to persist data to disc,
and can automatically clear out JWTs after they expire by utilizing the Time To
Live (TTL) functionality when storing a JWT. Here is an example using redis:

.. literalinclude:: ../examples/blocklist_redis.py

Database
~~~~~~~~
If you need to keep track of information about revoked JWTs our recommendation is
to utilize a database. This allows you to easily store and utilize metadata for
revoked tokens, such as when it was revoked, who revoked it, can it be un-revoked,
etc. Here is an example using SQLAlchemy:

.. literalinclude:: ../examples/blocklist_database.py
