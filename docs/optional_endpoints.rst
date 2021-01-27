Partially protecting routes
===========================

There may be cases where you want to use the same route regardless of if a JWT
is present in the requst or not. In these situations, you can use
:func:`~flask_jwt_extended.jwt_required` with the `optional=True` argument. This
will allow the endpoint to be accessed regardless of if a JWT is sent in with
the request.

If no JWT is present, :func:`~flask_jwt_extended.get_jwt` and
:func:`~flask_jwt_extended.get_jwt_header`, will return an empty dictionary.
:func:`~flask_jwt_extended.get_jwt_identity`, :attr:`~flask_jwt_extended.current_user`,
and :func:`~flask_jwt_extended.get_current_user` will return None.

If a JWT that is expired or not verifyable is in the request, an error will be
still returned like normal.


.. literalinclude:: ../examples/optional_protected_endpoints.py
