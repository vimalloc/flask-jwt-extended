JWT in Query String
===================

You can also pass the token in as a paramater in the query string instead of as
a header or a cookie (ex: /protected?jwt=<TOKEN>).  However, in almost all
cases it is recomended that you do not do this, as it comes with some security
issues. If you perform a GET request with a JWT in the query param, it is
possible that the browser will save the URL, which could lead to a leaked
token. It is also very likely that your backend (such as nginx or uwsgi) could
log the full url paths, which is obviously not ideal from a security standpoint.

If you do decide to use JWTs in query paramaters, here is an example of how
it might look:

.. literalinclude:: ../examples/jwt_in_query_string.py
