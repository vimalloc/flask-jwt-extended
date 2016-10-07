Adding Custom Data (Claims) to the Access Token
===============================================

You may want to store additional information in the access token. Perhaps you want to save the access roles this user has so you can access them in the view functions (without having to make a database call each time). This can be done with the user_claims_loader decorator, and accessed later with the 'get_jwt_claims()' method (in a protected endpoint).


.. code-block:: python

  from flask import Flask, jsonify, request
  from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
      get_jwt_claims

  app = Flask(__name__)
  app.secret_key = 'super-secret'  # Change this!
  jwt = JWTManager(app)


  # Using the user_claims_loader, we can specify a method that will be called
  # when creating access tokens, and add these claims to the said token. This
  # method is passed the identity of who the token is being created for, and
  # must return data that is json serializable
  @jwt.user_claims_loader
  def add_claims_to_access_token(identity):
      return {
          'hello': identity,
          'foo': ['bar', 'baz']
      }


  @app.route('/login', methods=['POST'])
  def login():
      username = request.json.get('username', None)
      password = request.json.get('password', None)
      if username != 'test' and password != 'test':
          return jsonify({"msg": "Bad username or password"}), 401

      ret = {'access_token': create_access_token(username)}
      return jsonify(ret), 200


  # In a protected view, get the claims you added to the jwt with the
  # get_jwt_claims() method
  @app.route('/protected', methods=['GET'])
  @jwt_required
  def protected():
      claims = get_jwt_claims()
      return jsonify({
          'hello_is': claims['hello'],
          'foo_is': claims['foo']
      }), 200

  if __name__ == '__main__':
      app.run()
