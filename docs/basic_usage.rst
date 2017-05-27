Basic Usage
===========

In its simplest form, there is not much to using flask_jwt_extended.

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
    "hello_from": "test"
  }

NOTE: Remember to change the secret key of your application, and insure that no
one is able to view it. The json web tokens are signed with the secret key, so
if someone gets that, they can create arbitrary tokens, and in essence log in
as any user.

Partially protecting routes
~~~~~~~~~~~~~~~~~~~~~~~~~~~

There may be cases where you want to use one endpoint for both protected
and unprotected data. In these situations, you can use the **jwt_optional**
decorator. This will allow the view to be called whether or not a token
is sent in the request, although if the token is expired or badly constructed,
or if the header is improperly formatted or otherwise incorrect, an error
will be returned.

.. code-block:: python

  @app.route('/partially-protected', methods=['GET'])
  @jwt_optional
  def partially_protected():
      # If no JWT is sent in the request headers, get_jwt_identity()
      # will return None
      current_user = get_jwt_identity()
      if current_user:
          return jsonify({'hello_from': current_user}), 200

      return jsonify({'hello_from': 'an anonymous user'}), 200

