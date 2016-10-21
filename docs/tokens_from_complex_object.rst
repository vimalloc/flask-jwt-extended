Tokens from Complex Objects
===========================

A common pattern will be to have your users information (such as username and
password) stored on disk somewhere. Lets say for example that we have a database
object stores a username, hashed password, and what roles this user is. In the
access token, we want the identity to be the username or user_id. We also want
to store the roles this user has access to in the access_token so that we don't
have to look that information up from the database on every request. We could
do this simple enough with the **user_claims_loader** mentioned in the last section.
However, is we pass just the identity (username or userid) to the **user_claims_loader**,
we would have to look up this user from the database twice. First time, when
they access the login endpoint and we need to verify their username and password,
and second time in the **user_claims_loader** function, so that we can fine what roles
this user has. This isn't a huge deal, but obviously it could be more efficient.

This extension provides the ability to pass any object to the **create_access_token**
method, which will then be passed to the **user_claims_loader** method. This lets
us access the database only once. However, as we still need the identity to be
a JSON serializable object unique to this user. We have a second jwt decorator
we can use for this, **user_identity_loader**. This lets you create a function
which takes any object passed in to the **create_access_token** and return
a json serializable identity from that object.

Here is an example of this in action

.. literalinclude:: ../examples/tokens_from_complex_objects.py
