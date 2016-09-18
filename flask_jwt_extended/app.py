from datetime import timedelta

import simplekv
import simplekv.memory
from flask import Flask, request, jsonify

from flask_jwt_extended import JWTManager, jwt_required, fresh_jwt_required,\
    create_refresh_access_tokens, create_fresh_access_token, refresh_access_token,\
    jwt_identity, jwt_claims, revoke_token, unrevoke_token, get_stored_tokens

# Example users database
USERS = {
    'test1': {
        'id': 1,
        'password': 'abc123',
        'type': 'restricted'
    },
    'test2': {
        'id': 2,
        'password': 'abc123',
        'type': 'admin'
    },
}

# Flask test stuff
app = Flask(__name__)
app.debug = True
app.secret_key = 'super-secret'

# Optional configuration options for flask_jwt_extended
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # defaults to 15 minutes
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)  # defaults to 30 days
app.config['JWT_ALGORITHM'] = 'HS512'  # Default to HS256

# Enable JWT blacklist / token revoke
app.config['JWT_BLACKLIST_ENABLED'] = True

# We are going to be using a simple in memory blacklist for this example. In
# production, you will likely prefer something like redis (it can work with
# multiple threads and processes, and supports automatic removal of expired
# tokens so the blacklist doesn't blow up). Check here for available options:
# http://pythonhosted.org/simplekv/
blacklist_store = simplekv.memory.DictStore()
app.config['JWT_BLACKLIST_STORE'] = blacklist_store

# Only check the blacklist for refresh token. Available options are:
#   'all': Check blacklist for access and refresh tokens
#   'refresh': Check blacklist only for refresh tokens
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'

jwt = JWTManager(app)


# Function to add custom claims to the JWT (optional).
@jwt.user_claims_loader
def my_claims(identity):
    return {
        'type': USERS[identity]['type'],
        'ip': request.remote_addr
    }


# Function to change the result if someone without a token tries to access a
# protected endpoint (optional)
@jwt.unauthorized_loader
def my_unauthorized_response():
    return jsonify({
        'status': 401,
        'sub_status': 100,
        'message': 'You must submit a valid JWT to access this endpoint',
    })


# Function to change the result if someone with an expired token tries
# to access a protected endpoint (optional)
@jwt.expired_token_loader
def my_expired_response():
    return jsonify({
        'status': 401,
        'sub_status': 101,
        'message': 'Token expired',
    })


# Endpoint for authing a user
@app.route('/auth/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({"msg": "Bad username or password"}), 401
    if USERS[username]['password'] != password:
        return jsonify({"msg": "Bad username or password"}), 401

    return create_refresh_access_tokens(identity=username)


# Endpoint for getting a fresh access token for a user
@app.route('/auth/fresh-login', methods=['POST'])
def fresh_login():
    username = request.json.get('username', None)
    password = request.json.get('username', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({"msg": "Bad username or password"}), 401
    if USERS[username]['password'] != password:
        return jsonify({"msg": "Bad username or password"}), 401

    return create_fresh_access_token(identity=username)


# Endpoint for listing tokens
@app.route('/auth/tokens', methods=['GET'])
def list_tokens():
    # TODO you should put some extra protection on this, so a user can only
    #      view their tokens, or some extra privillage roles so an admin can
    #      view everyones token
    return jsonify(get_stored_tokens()), 200


# Endpoint for revoking and unrevoking tokens
@app.route('/auth/tokens/<string:jti>', methods=['PUT'])
def revoke_jwt(jti):
    # TODO you should put some extra protection on this, so a user can only
    #      modify their tokens
    revoke = request.json.get('revoke', None)
    if revoke is None:
        return jsonify({'msg': "Missing json argument: 'revoke'"}), 422
    if not isinstance(revoke, bool):
        return jsonify({'msg': "revoke' must be a boolean"}), 422

    if revoke:
        revoke_token(jti)
    else:
        unrevoke_token(jti)


# Endpoint for generating a non-fresh access token from the refresh token
@app.route('/auth/refresh', methods=['POST'])
def refresh_token():
    return refresh_access_token()


@app.route('/protected', methods=['GET'])
@jwt_required
def non_fresh_protected():
    ip = jwt_claims['ip']  # Access data stored in custom claims on the JWT
    username = jwt_identity  # Access identity through jwt_identity proxy

    msg = '{} says hello from {}'.format(username, ip)
    return jsonify({'msg': msg})


@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def fresh_protected():
    ip = jwt_claims['ip']  # Access data stored in custom claims on the JWT
    username = jwt_identity  # Access identity through jwt_identity proxy

    msg = '{} says hello from {} (fresh)'.format(username, ip)
    return jsonify({'msg': msg})

if __name__ == '__main__':
    app.run()
