Storing Additional Data in JWTs
===============================
You may want to store additional information in the access token which you could
later access in the protected views. This can be done using the ``additional_claims``
argument with the :func:`~flask_jwt_extended.create_access_token` or
:func:`~flask_jwt_extended.create_refresh_token` functions. The claims
can be accessed in a protected route via the :func:`~flask_jwt_extended.get_jwt`
function.

It is important to remember that JWTs are not encrypted and the contents of
a JWT can be trivially decoded by anyone who has access to it. As such, you
should never put any sensitive information in a JWT.

.. literalinclude:: ../examples/additional_data_in_access_token.py


Alternately you can use the :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader`
decorator to register a callback function that will be called whenever a new JWT
is created, and return a dictionary of claims to add to that token. In the case
that both :meth:`~flask_jwt_extended.JWTManager.additional_claims_loader` and the
``additional_claims`` argument are used, both results are merged together, with ties
going to the data supplied by the ``additional_claims`` argument.

.. code-block:: python

  # Using the additional_claims_loader, we can specify a method that will be
  # called when creating JWTs. The decorated method must take the identity
  # we are creating a token for and return a dictionary of additional
  # claims to add to the JWT.
  @jwt.additional_claims_loader
  def add_claims_to_access_token(identity):
       return {
           "aud": "some_audience",
           "foo": "bar",
           "upcase_name": identity.upper(),
       }
