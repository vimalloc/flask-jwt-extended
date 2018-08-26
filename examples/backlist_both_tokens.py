from flask_jwt_extended import decode_token


# Endpoint for loggin in
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' or password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    user = {id: 1, username: 'test'}
    refresh_token = create_refresh_token(identity=user)

    # Embed the refresh token's jti in the access_token
    user["refresh_jti"] = decode_token(refresh_token)["jti"]
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


# Endpoint which backlists both the refresh token and the access token with a
# single call
@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    access_jti = get_raw_jwt()["jti"]
    refresh_jti = get_raw_jwt()["identity"]["refresh_jti"]
    backlist.add(access_jti)
    backlist.add(refresh_jti)
    return jsonify({"msg": "Successfully logged out"}), 200
