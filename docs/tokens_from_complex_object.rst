Tokens from Complex Objects
===========================

A common pattern will be to have your users information (such as username and
password) stored on disk somewhere. Lets say for example that we have a database
which contains usernames, hashed passwords, and user roles. In the
access token, we want the identity to be the username, and we want
to store the users role as an additional claim.  We can do this with the
**user_claims_loader** mentioned in the last section. However, is we pass just
the identity (username) to the **user_claims_loader**,
we would have to look up this user from the database twice. First time, when
they access the login endpoint and we need to verify their username and password,
and second time in the **user_claims_loader** function, so that we can fine what roles
this user has. This isn't a huge deal, but obviously it could be more efficient.

This extension provides the ability to pass any object to the **create_access_token**
method, which will then be passed to the **user_claims_loader** method. This lets
us access the database only once. However, we still need to pull the username
out of the object, to set as the identity for the access token. We have a second
decorator we can use for this, **user_identity_loader**. This lets you create a
function which takes any object passed in to the **create_access_token** and return
a json serializable identity from that object.

Here is an example of this in action

.. literalinclude:: ../examples/tokens_from_complex_objects.py
