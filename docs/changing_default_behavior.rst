Changing Default Behaviors
==========================


We provide what we think are sensible behaviors when attempting to access a protected endpoint. If the access token is not valid for any reason (missing, expired, tampered with, etc) we will return json in the format of {'msg': 'why accessing endpoint failed'} along with an appropriate http status code (generally 401 or 422). However, you may want to customize what you returned in these situations. We can do that with the jwt_manager _loader functions.


.. code-block:: python

  from flask import Flask, jsonify, request
  from flask_jwt_extended import JWTManager, jwt_required, create_access_token

  app = Flask(__name__)
  app.secret_key = 'super-secret'  # Change this!
  jwt = JWTManager(app)


  # Use the expired_token_loader to call this function whenever an expired but
  # otherwise valid access token tries to access an endpoint
  @jwt.expired_token_loader
  def my_expired_token_callback():
      return jsonify({
          'status': 401,
          'sub_status': 101,
          'msg': 'The token has expired'
      }), 200


  @app.route('/login', methods=['POST'])
  def login():
      username = request.json.get('username', None)
      password = request.json.get('password', None)
      if username != 'test' and password != 'test':
          return jsonify({"msg": "Bad username or password"}), 401

      ret = {'access_token': create_access_token(username)}
      return jsonify(ret), 200


  @app.route('/protected', methods=['GET'])
  @jwt_required
  def protected():
      return jsonify({'hello': 'world'}), 200

  if __name__ == '__main__':
      app.run()



************************************
Loader functions are:
************************************

.. automodule:: jwt_manager.py
  :members:

.. literalinclude:: ../flask_jwt_extended/jwt_manager.py
  :language: python
  :emphasize-lines: 60-122
  :linenos:
