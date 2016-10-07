Basic Usage
===========


In its simplest form, there is not much to using flask_jwt_extended.


.. code-block :: python

  from flask import Flask, jsonify, request
  from flask_jwt_extended import JWTManager, jwt_required, create_access_token

  app = Flask(__name__)
  app.secret_key = 'super-secret'  # Change this!

  # Setup the Flask-JWT-Extended extension
  jwt = JWTManager(app)


  # Provide a method to create access tokens. The create_access_token() function
  # is used to actually generate the token
  @app.route('/login', methods=['POST'])
  def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {'access_token': create_access_token(username)}
    return jsonify(ret), 200


  # Protect a view with jwt_required, which requires a valid access token in the
  # request to access.
  @app.route('/protected', methods=['GET'])
  @jwt_required
  def protected():
    return jsonify({'hello': 'world'}), 200

  if __name__ == '__main__':
    app.run()


To access a jwt_required protected view, all we have to do is send an authorization head with the request that include the token. The header looks like this:


.. code-block :: bash

  Authorization: Bearer <access_token>


We can see this in action using CURL:

.. code-block :: bash

  $ curl --write-out "%{http_code}\n"  http://localhost:5000/protected
  {
    "msg": "Missing Authorization Header"
  }
  401

  $ curl --write-out "%{http_code}\n" -H "Content-Type: application/json" -X POST -d '{"username":"test","password":"test"}' http://localhost:5000/login
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwianRpIjoiZjhmNDlmMjUtNTQ4OS00NmRjLTkyOWUtZTU2Y2QxOGZhNzRlIiwidXNlcl9jbGFpbXMiOnt9LCJuYmYiOjE0NzQ0NzQ3OTEsImlhdCI6MTQ3NDQ3NDc5MSwiaWRlbnRpdHkiOiJ0ZXN0IiwiZXhwIjoxNDc0NDc1NjkxLCJ0eXBlIjoiYWNjZXNzIn0.vCy0Sec61i9prcGIRRCbG8e9NV6_wFH2ICFgUGCLKpc"
  }
  200

  $ export ACCESS="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwianRpIjoiZjhmNDlmMjUtNTQ4OS00NmRjLTkyOWUtZTU2Y2QxOGZhNzRlIiwidXNlcl9jbGFpbXMiOnt9LCJuYmYiOjE0NzQ0NzQ3OTEsImlhdCI6MTQ3NDQ3NDc5MSwiaWRlbnRpdHkiOiJ0ZXN0IiwiZXhwIjoxNDc0NDc1NjkxLCJ0eXBlIjoiYWNjZXNzIn0.vCy0Sec61i9prcGIRRCbG8e9NV6_wFH2ICFgUGCLKpc"

  $ curl --write-out "%{http_code}\n" -H "Authorization: Bearer $ACCESS" http://localhost:5000/protected
  {
    "hello": "world"
  }
  200
