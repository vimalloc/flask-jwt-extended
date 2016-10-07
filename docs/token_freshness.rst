Token Freshness
================



We have the idea of token freshness built into this extension. In a nutshell, you can choose to mark some access tokens as fresh and others as non-fresh, and use the fresh_jwt_required decorator to only allow fresh tokens to access some views.

This is useful for allowing fresh tokens to do some critical things (maybe change a password, or complete an online purchase), but to deny those features to non-fresh tokens without forcing them to re-authenticate. This still allows your users to access any of the normal jwt_protected endpoints while using a non-fresh token. Using these can lead to a more secure site, without creating a burden on the users experiences by forcing them to re-authenticate all the time.

The provided API gives you the power to use the token freshness however you may want to. A very natural way to do this would be to mark a token as fresh when they first login, mark any tokens generated with the refresh token to as not fresh.


.. code-block:: python


  from flask import Flask, jsonify, request
  from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
      jwt_refresh_token_required, create_refresh_token, get_jwt_identity, \
      fresh_jwt_required

  app = Flask(__name__)
  app.secret_key = 'super-secret'  # Change this!
  jwt = JWTManager(app)


  # Standard login endpoint. Will return a fresh access token and a refresh token
  @app.route('/login', methods=['POST'])
  def login():
      username = request.json.get('username', None)
      password = request.json.get('password', None)
      if username != 'test' and password != 'test':
          return jsonify({"msg": "Bad username or password"}), 401

      # create_access_token supports an optional 'fresh' argument, which marks the
      # token as fresh or non-fresh accordingly. As we just verified their username
      # and password, we are going to mark the token as fresh here.
      ret = {
          'access_token': create_access_token(identity=username, fresh=True),
          'refresh_token': create_refresh_token(identity=username)
      }
      return jsonify(ret), 200


  # Fresh login endpoint. This is designed to be used if we need to make a fresh
  # token for a user (by verifying they have the correct username and password).
  # Unlike the standard login endpoint, this will only return a new access token
  # (so that we don't keep generating new refresh tokens, which defeats their point)
  @app.route('/fresh-login', methods=['POST'])
  def fresh_login():
      username = request.json.get('username', None)
      password = request.json.get('password', None)
      if username != 'test' and password != 'test':
          return jsonify({"msg": "Bad username or password"}), 401

      ret = {'access_token': create_access_token(identity=username, fresh=True)}
      return jsonify(ret), 200


  # Refresh token endpoint. This will generate a new access token from the refresh
  # token, but will mark that access token as non-fresh (so that it cannot access
  # any endpoint protected via the fresh_jwt_required decorator)
  @app.route('/refresh', methods=['POST'])
  @jwt_refresh_token_required
  def refresh():
      current_user = get_jwt_identity()
      ret = {
          'access_token': create_access_token(identity=current_user, fresh=False)
      }
      return jsonify(ret), 200


  # Any valid jwt can access this endpoint
  @app.route('/protected', methods=['GET'])
  @jwt_required
  def protected():
      username = get_jwt_identity()
      return jsonify({'hello': 'from {}'.format(username)}), 200


  # Only fresh jwts can access this endpoint
  @app.route('/protected-fresh', methods=['GET'])
  @fresh_jwt_required
  def protected_fresh():
      username = get_jwt_identity()
      return jsonify({'hello': 'from {}'.format(username)}), 200

  if __name__ == '__main__':
      app.run()
