Tokens from Complex Objects
===========================

A very common setup is to have your users information (usernames,
passwords, roles, etc) stored in a database. Now, lets pretend that we want to
create an access tokens where the tokens identity is a username, and we also want
to store a users roles as an additional claim in the token. We can do
this with the :meth:`~flask_jwt_extended.JWTManager.user_claims_loader`
decorator, discussed in the previous section. However, if we pass the username
to the :meth:`~flask_jwt_extended.JWTManager.user_claims_loader`, we would end
up needing to query this user from the database two times. The first time would
be when login endpoint is hit and we need to verify a username and password.
The second time would be in the
:meth:`~flask_jwt_extended.JWTManager.user_claims_loader`
function, because we need to query the roles for this user. This isn't a huge
deal, but obviously it could be more efficient.

This extension provides the ability to pass any object to the
:func:`~flask_jwt_extended.create_access_token` function, which will then be
passed as is to the :meth:`~flask_jwt_extended.JWTManager.user_claims_loader`.
This allows us access the database only once, but introduces a new
issue that needs to be addressed. We still need to pull the username
out of the object, so that we can have the username be the identity for the
new token. We have a second decorator we can use for this,
:meth:`~flask_jwt_extended.JWTManager.user_identity_loader`, which lets you
take any object passed in to :func:`~flask_jwt_extended.create_access_token`
and return a json serializable identity from that object.

Here is an example of this in action:

.. literalinclude:: ../examples/tokens_from_complex_objects.py
