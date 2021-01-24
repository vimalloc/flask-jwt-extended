Partially protecting routes
===========================

There may be cases where you want to use one endpoint for both protected
and unprotected data. In these situations, you can use the
:func:`~flask_jwt_extended.jwt_required` decorator. This will allow the endpoint
to be accessed regardless of if a JWT is sent in with the request. If a JWT
that is expired or badly constructed is sent in with the request, an error will
be returned instead of calling the protected endpoint as if no token was
present in the request.

.. literalinclude:: ../examples/optional_protected_endpoints.py
