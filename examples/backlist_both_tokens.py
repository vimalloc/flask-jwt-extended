from flask import Flask, request, jsonify

from flask_jwt_extended import (
    jwt_refresh_token_required, jwt_required, create_access_token, get_jti,
    create_refresh_token, get_jwt_identity, get_raw_jwt, JWTManager
)


app = Flask(__name__)

# Enable blacklisting and specify what kind of tokens to check
# against the blacklist
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

blacklist = set()


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


# Endpoint for logging in
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' or password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # use a dict for identity, so that we can link the access token with
    # the refresh token as a user claim
    user = {"username": username}
    refresh_token = create_refresh_token(identity=user)

    # Embed the refresh token's jti in the access_token
    user["refresh_jti"] = get_jti(refresh_token)
    access_token = create_access_token(identity=user)

    ret = {
        'access_token': access_token,
        'refresh_token': refresh_token
    }
    return jsonify(ret), 200


# Endpoint for generating a new access token using refresh token
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    refresh_jti = get_raw_jwt()['jti']
    current_user['refresh_jti'] = refresh_jti
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200


# Endpoint which blacklists both the refresh token and the access token with a
# single call
@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    access_jti = get_raw_jwt()["jti"]
    refresh_jti = get_jwt_identity()["refresh_jti"]
    blacklist.add(access_jti)
    blacklist.add(refresh_jti)
    return jsonify({"msg": "Successfully logged out"}), 200


if __name__ == "__main__":
    app.run()
