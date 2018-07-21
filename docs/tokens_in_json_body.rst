JWT in JSON Body
================

You can also pass the token as an attribute in the body of an `application/json` request.
However, since the body is meaningless in a `GET` request, this is mostly useful for
protecting routes that only accept `POST`, `PATCH`, or `DELETE` methods.

That is to say, the `GET` method will become essentially unauthorized in any protected route
if you only use this lookup method.

If you decide to use JWTs in the request body, here is an example of how it might look:

.. literalinclude:: ../examples/jwt_in_json.py
