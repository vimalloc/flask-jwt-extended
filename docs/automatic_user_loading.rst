Automatic User Loading
======================

In most web applications it is important to have access to the user who is
accessing a protected route. We provide a couple callback functions that make
this seemless while working with JWTs.

The first is :meth:`~flask_jwt_extended.JWTManager.user_identity_loader`, which
will convert any ``User`` object used to create a JWT into a JSON serializable format.

On the flip side, you can use :meth:`~flask_jwt_extended.JWTManager.user_lookup_loader`
to automaticallly load your ``User`` object when a JWT is present in the request.
The loaded user is available in your protected routes via :attr:`~flask_jwt_extended.current_user`.

Lets see an example of this while utilizing SQLAlchemy to store our users:

.. literalinclude:: ../examples/automatic_user_loading.py

We can see this in action using `HTTPie <https://httpie.io/>`_.

.. code-block :: bash

  $ http POST :5000/login username=panther password=password

  HTTP/1.0 200 OK
  Content-Length: 281
  Content-Type: application/json
  Date: Sun, 24 Jan 2021 17:23:31 GMT
  Server: Werkzeug/1.0.1 Python/3.8.6

  {
      "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxMTUwOTAxMSwianRpIjoiNGFmN2ViNTAtMjk3Yy00ZmY4LWJmOTYtMTZlMDE5MWEzYzMwIiwibmJmIjoxNjExNTA5MDExLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoyLCJleHAiOjE2MTQxMDEwMTF9.2UhZo-xo19NXaqKLwcMz0NBLAcxxEUeK4Ziqk1T_9h0"
  }


  $ export JWT="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTYxMTUwOTAxMSwianRpIjoiNGFmN2ViNTAtMjk3Yy00ZmY4LWJmOTYtMTZlMDE5MWEzYzMwIiwibmJmIjoxNjExNTA5MDExLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoyLCJleHAiOjE2MTQxMDEwMTF9.2UhZo-xo19NXaqKLwcMz0NBLAcxxEUeK4Ziqk1T_9h0"


  $ http GET :5000/who_am_i Authorization:"Bearer $JWT"

  HTTP/1.0 200 OK
  Content-Length: 57
  Content-Type: application/json
  Date: Sun, 24 Jan 2021 17:31:34 GMT
  Server: Werkzeug/1.0.1 Python/3.8.6

  {
      "id": 2,
      "full_name": "Ann Takamaki",
      "username": "panther"
  }
