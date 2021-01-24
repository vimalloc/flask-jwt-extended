Basic Usage
===========

In its simplest form, there is not much to using this extension. You use
:func:`~flask_jwt_extended.create_access_token` to make JSON Web Tokens,
:func:`~flask_jwt_extended.jwt_required` to protect routes, and
:func:`~flask_jwt_extended.get_jwt_identity` to get the identity of a JWT in a
protected route.

.. literalinclude:: ../examples/simple.py

To access a jwt_required protected view you need to send in the JWT with each
request. By default, this is done with an authorization header that looks like:

.. code-block :: bash

  Authorization: Bearer <access_token>


We can see this in action using `HTTPie <https://httpie.io/>`_.

.. code-block :: bash

  $ http GET :5000/protected

  HTTP/1.0 401 UNAUTHORIZED
  Content-Length: 39
  Content-Type: application/json
  Date: Sun, 24 Jan 2021 18:09:17 GMT
  Server: Werkzeug/1.0.1 Python/3.8.6

  {
      "msg": "Missing Authorization Header"
  }


  $ http POST :5000/login username=test password=test

  HTTP/1.0 200 OK
  Content-Length: 288
  Content-Type: application/json
  Date: Sun, 24 Jan 2021 18:10:39 GMT
  Server: Werkzeug/1.0.1 Python/3.8.6

  {
      "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxMTUxMTgzOSwianRpIjoiMmI0NzliNTQtYTI0OS00ZDNjLWE4NjItZGVkZGIzODljNmVlIiwibmJmIjoxNjExNTExODM5LCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoidGVzdCIsImV4cCI6MTYxNDEwMzgzOX0.UpTueBRwNLK8e-06-oo5Y_9eWbaN5T3IHwKsy6Jauaw"
  }


  $ export JWT="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxMTUxMTgzOSwianRpIjoiMmI0NzliNTQtYTI0OS00ZDNjLWE4NjItZGVkZGIzODljNmVlIiwibmJmIjoxNjExNTExODM5LCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoidGVzdCIsImV4cCI6MTYxNDEwMzgzOX0.UpTueBRwNLK8e-06-oo5Y_9eWbaN5T3IHwKsy6Jauaw"


  $ http GET :5000/protected Authorization:"Bearer $JWT"

  HTTP/1.0 200 OK
  Content-Length: 24
  Content-Type: application/json
  Date: Sun, 24 Jan 2021 18:12:02 GMT
  Server: Werkzeug/1.0.1 Python/3.8.6

  {
      "logged_in_as": "test"
  }

**Important**

Remember to change the jwt secret key in your application, and ensure that it
is secure. The JWTs are signed with this key, and if someone gets their hands
on it they will be able to create arbitraty tokens that are accepted by your
web flask application.
