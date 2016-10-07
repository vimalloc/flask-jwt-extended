Blacklist and Token Revoking
============================

This supports optional blacklisting and token revoking out of the box. This will allow you to revoke a specific token so a user can no longer access your endpoints. In order to revoke a token, we need some storage where we can save a list of all the tokens we have created, as well as if they have been revoked or not. In order to make the underlying storage as agnostic as possible, we use simplekv to provide assess to a variety of backends.

In production, it is important to use a backend that can have some sort of persistent storage, so we don't 'forget' that we revoked a token if the flask process is restarted. We also need something that can be safely used by the multiple thread and processes running your application. At present we believe redis is a good fit for this. It has the added benefit of removing expired tokens from the store automatically, so it wont blow up into something huge.

We also have choose what tokens we want to check against the blacklist. We could check all tokens (refresh and access), or only the refresh tokens. There are pros and cons to either way (extra overhead on jwt_required endpoints vs someone being able to use an access token freely until it expires). In this example, we are going to only check refresh tokens, and set the access tokes to a small expires time to help minimize damage that could be done with a stolen access token.

.. code-block:: python

  from datetime import timedelta
  

  import simplekv
  import simplekv.memory
  from flask import Flask, request, jsonify

  from flask_jwt_extended import JWTManager, jwt_required, \
      get_jwt_identity, revoke_token, unrevoke_token, \
      get_stored_tokens, get_all_stored_tokens, create_access_token, \
      create_refresh_token, jwt_refresh_token_required

  # Setup flask
  app = Flask(__name__)
  app.secret_key = 'super-secret'

  # Configure access token expires time
  app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)

  # Enable and configure the JWT blacklist / token revoke. We are using an in
  # memory store for this example. In production, you should use something
  # persistant (such as redis, memcached, sqlalchemy). See here for options:
  # http://pythonhosted.org/simplekv/
  app.config['JWT_BLACKLIST_ENABLED'] = True
  app.config['JWT_BLACKLIST_STORE'] = simplekv.memory.DictStore()
  app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'

  jwt = JWTManager(app)


  @app.route('/login', methods=['POST'])
  def login():
      username = request.json.get('username', None)
      password = request.json.get('password', None)
      if username != 'test' and password != 'test':
          return jsonify({"msg": "Bad username or password"}), 401

      ret = {
          'access_token': create_access_token(identity=username),
          'refresh_token': create_refresh_token(identity=username)
      }
      return jsonify(ret), 200


  @app.route('/refresh', methods=['POST'])
  @jwt_refresh_token_required
  def refresh():
      current_user = get_jwt_identity()
      ret = {
          'access_token': create_access_token(identity=current_user)
      }
      return jsonify(ret), 200


  # Endpoint for listing tokens that have the same identity as you
  @app.route('/auth/tokens', methods=['GET'])
  @jwt_required
  def list_identity_tokens():
      username = get_jwt_identity()
      return jsonify(get_stored_tokens(username)), 200


  # Endpoint for listing all tokens. In your app, you should either not expose
  # this endpoint, or put some addition security on top of it so only trusted users,
  # (administrators, etc) can access it
  @app.route('/auth/all-tokens')
  def list_all_tokens():
      return jsonify(get_all_stored_tokens()), 200


  # Endpoint for allowing users to revoke their tokens
  @app.route('/auth/tokens/revoke/<string:jti>', methods=['PUT'])
  @jwt_required
  def change_jwt_revoke_state(jti):
      username = jwt_get_identity()
      try:
          token_data = get_stored_token(jti)
          if token_data['token']['identity'] != username:
              raise KeyError
          revoke_token(jti)
          return jsonify({"msg": "Token successfully revoked"}), 200
      except KeyError:
          return jsonify({'msg': 'Token not found'}), 404


  # Endpoint for allowing users to unrevoke their tokens
  @app.route('/auth/tokens/unrevoke/<string:jti>', methods=['PUT'])
  @jwt_required
  def change_jwt_unrevoke_state(jti):
      username = jwt_get_identity()
      try:
          token_data = get_stored_token(jti)
          if token_data['token']['identity'] != username:
              raise KeyError
          unrevoke_token(jti)
          return jsonify({"msg": "Token successfully unrevoked"}), 200
      except KeyError:
          return jsonify({'msg': 'Token not found'}), 404


  @app.route('/protected', methods=['GET'])
  @jwt_required
  def protected():
      return jsonify({'hello': 'world'})

  if __name__ == '__main__':
      app.run()
