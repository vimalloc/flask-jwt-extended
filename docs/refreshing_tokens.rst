Refreshing Tokens
=================
In most web applications, it would not be ideal if a user was logged out in the
middle of doing something because their JWT expired. Unfortunately we can't just
change the expires time on a JWT on each request, as once a JWT is created it
cannot be modified, only replaced with a new JWT. Lets take a look at how we can
simulate these behaviors.

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
TODO

.. literalinclude:: ../examples/refresh_tokens.py
