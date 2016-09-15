from flask import Flask, request, jsonify

# TODO fix __init__.py to make imports easier
from flask_jwt_extended.jwt_manager import JWTManager
from flask_jwt_extended.utils import jwt_required, fresh_jwt_required, jwt_auth,\
    jwt_identity, jwt_refresh, jwt_fresh_login

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
jwt = JWTManager(app)


# Function to add custom claims to the JWT
@jwt.user_claims_loader
def jwt_user_claims(identity):
    return {
        'type': USERS[identity]['type'],
        'ip': request.remote_addr
    }


# Endpoint for authing a user
@app.route('/auth', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('username', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({"msg": "Bad username or password"}), 401
    if USERS[username]['password'] != password:
        return jsonify({"msg": "Bad username or password"}), 401

    return jwt_auth(identity=username)


# Endpoint for getting a fresh access token for a user
@app.route('/fresh-auth', methods=['POST'])
def fresh_login():
    username = request.json.get('username', None)
    password = request.json.get('username', None)
    if username is None or password is None:
        return jsonify({"msg": "Missing username or password"}), 422

    if username not in USERS:
        return jsonify({"msg": "Bad username or password"}), 401
    if USERS[username]['password'] != password:
        return jsonify({"msg": "Bad username or password"}), 401

    return jwt_fresh_login(identity=username)


# Endpoint for generating a non-fresh access token from the refresh token
@app.route('/refresh', methods=['POST'])
def refresh_token():
    return jwt_refresh()


@app.route('/protected', methods=['GET'])
@jwt_required
def non_fresh_protected():
    ip = jwt_user_claims['ip']
    msg = '{} says hello from {}'.format(jwt_identity, ip)
    return jsonify({'msg': msg})


@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def fresh_protected():
    ip = jwt_user_claims['ip']
    msg = '{} says hello from {} (fresh)'.format(jwt_identity, ip)
    return jsonify({'msg': msg})

if __name__ == '__main__':
    app.run()
