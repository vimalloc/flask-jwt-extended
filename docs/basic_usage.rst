Basic Usage
===========

In its simplest form, there is not much to using flask_jwt_extended. You use
:func:`~flask_jwt_extended.create_access_token` to make new access JWTs,
the :func:`~flask_jwt_extended.jwt_required` decorator to protect endpoints,
and :func:`~flask_jwt_extended.get_jwt_identity` function to get the identity
of a JWT in a protected endpoint.

.. literalinclude:: ../examples/simple.py

To access a jwt_required protected view, all we have to do is send in the
JWT with the request. By default, this is done with an authorization header
that looks like:

.. code-block :: bash

  Authorization: Bearer <access_token>


We can see this in action using CURL:

.. code-block :: bash

  $ curl http://localhost:5000/protected
  {
    "msg": "Missing Authorization Header"
  }

  $ curl -H "Content-Type: application/json" -X POST \
    -d '{"username":"test","password":"test"}' http://localhost:5000/login
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwianRpIjoiZjhmNDlmMjUtNTQ4OS00NmRjLTkyOWUtZTU2Y2QxOGZhNzRlIiwidXNlcl9jbGFpbXMiOnt9LCJuYmYiOjE0NzQ0NzQ3OTEsImlhdCI6MTQ3NDQ3NDc5MSwiaWRlbnRpdHkiOiJ0ZXN0IiwiZXhwIjoxNDc0NDc1NjkxLCJ0eXBlIjoiYWNjZXNzIn0.vCy0Sec61i9prcGIRRCbG8e9NV6_wFH2ICFgUGCLKpc"
  }

  $ export ACCESS="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwianRpIjoiZjhmNDlmMjUtNTQ4OS00NmRjLTkyOWUtZTU2Y2QxOGZhNzRlIiwidXNlcl9jbGFpbXMiOnt9LCJuYmYiOjE0NzQ0NzQ3OTEsImlhdCI6MTQ3NDQ3NDc5MSwiaWRlbnRpdHkiOiJ0ZXN0IiwiZXhwIjoxNDc0NDc1NjkxLCJ0eXBlIjoiYWNjZXNzIn0.vCy0Sec61i9prcGIRRCbG8e9NV6_wFH2ICFgUGCLKpc"

  $ curl -H "Authorization: Bearer $ACCESS" http://localhost:5000/protected
  {
    "logged_in_as": "test"
  }

NOTE: Remember to change the secret key of your application, and ensure that no
one is able to view it. The JSON Web Tokens are signed with the secret key, so
if someone gets that, they can create arbitrary tokens, and in essence log in
as any user.
