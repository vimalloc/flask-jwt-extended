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
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxMTQ2MzE4MCwianRpIjoiZTBjMzhhNDUtNGM5My00NTJmLWIzZWQtOTcyZGJiNzA5YWViIiwibmJmIjoxNjExNDYzMTgwLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoidGVzdCIsImV4cCI6MTYxNDA1NTE4MH0.Qc87HZBv_qBlzcybCMoeh0SM2oyM6Waefw_xEP0VdF8"
  }

  $ export JWT="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxMTQ2MzE4MCwianRpIjoiZTBjMzhhNDUtNGM5My00NTJmLWIzZWQtOTcyZGJiNzA5YWViIiwibmJmIjoxNjExNDYzMTgwLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoidGVzdCIsImV4cCI6MTYxNDA1NTE4MH0.Qc87HZBv_qBlzcybCMoeh0SM2oyM6Waefw_xEP0VdF8"

  $ curl -H "Authorization: Bearer $JWT" http://localhost:5000/protected
  {
    "logged_in_as": "test"
  }

**Important**

Remember to change the jwt secret key in your application, and ensure that it
is secure. The JWTs are signed with this key, and if someone gets their hands
on it they will be able to create arbitraty tokens that are accepted by your
web flask application.
