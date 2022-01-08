Refreshing Tokens
=================
In most web applications, it would not be ideal if a user was logged out in the
middle of doing something because their JWT expired. Unfortunately we can't just
change the expires time on a JWT on each request, as once a JWT is created it
cannot be modified. Lets take a look at some options for solving this problem
by refreshing JWTs.

Implicit Refreshing With Cookies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
One huge benefit to storing your JWTs in cookies (when your frontend is a website)
is that the frontend does not have to handle any logic when it comes to refreshing
a token. It can all happen implicitly with the cookies your Flask application sets.

The basic idea here is that at the end of every request, we will check if there
is a JWT that is close to expiring. If we find a JWT that is nearly expired,
we will replace the current cookie containing the JWT with a new JWT that has a
longer time until it expires.

This is our recommended approach when your frontend is a website.

.. literalinclude:: ../examples/implicit_refresh.py


Explicit Refreshing With Refresh Tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Alternatively, this extension comes out of the box with refresh token support.
A refresh token is a long lived JWT that can only be used to creating new access
tokens.

You have a couple choices about how to utilize a refresh token. You could store
the expires time of your access token on your frontend, and each time you make
an API request first check if the current access token is near or already
expired, and refresh it as needed. This approach is pretty simple and will work
fine in most cases, but do be aware that if your frontend has a clock that is
significantly off, you might run into issues.

An alternative approach involves making an API request with your access token
and then checking the result to see if it worked. If the result of the request
is an error message saying that your token is expired, use the refresh token to
generate a new access token and redo the request with the new token. This approach
will work regardless of the clock on your frontend, but it does require having
some potentially more complicated logic.

Using refresh tokens is our recommended approach when your frontend is not a
website (mobile, api only, etc).

.. literalinclude:: ../examples/refresh_tokens.py

Making a request with a refresh token looks just like making a request with
an access token. Here is an example using `HTTPie <https://httpie.io/>`_.

.. code-block :: bash

 $ http POST :5000/refresh Authorization:"Bearer $REFRESH_TOKEN"


Token Freshness Pattern
~~~~~~~~~~~~~~~~~~~~~~~
The token freshness pattern is a very simple idea. Every time a user authenticates
by providing a username and password, they receive a ``fresh`` access token that
can access any route. But after some time, that token should no longer be considered
``fresh``, and some critical or dangerous routes will be blocked until the user
verifies their password again. All other routes will still work normally for
the user even though their token is no longer ``fresh``. As an example, we might
not allow users to change their email address unless they have a ``fresh`` token,
but we do allow them use the rest of our Flask application normally.

The token freshness pattern is built into this extension, and works seamlessly
with both token refreshing strategies discussed above. Lets take a look at this
with the explicit refresh example (it will look basically same in the implicit
refresh example).

.. literalinclude:: ../examples/token_freshness.py

We also support marking a token as fresh for a given amount of time after it
is created. You can do this by passing a ``datetime.timedelta`` to the ``fresh``
option when creating JWTs:

.. code-block :: python

  create_access_token(identity, fresh=datetime.timedelta(minutes=15))


Revoking Refresh Tokens
~~~~~~~~~~~~~~~~~~~~~~~
Note that when an access token is invalidated (e.g. logging a user out), the
corresponding refresh token(s) must be revoked too.
See :ref:`Handling Revoking Refresh Tokens` for details on how to handle this.
