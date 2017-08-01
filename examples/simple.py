from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required,\
    create_access_token, get_jwt_identity

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!

# Setup the Flask-JWT-Extended extension
jwt = JWTManager(app)


# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token
@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        params = request.get_json()
        if 'username' in params.keys() and 'password' in params.keys():
            if params['username'] != 'test' or params['password'] != 'test':
                return jsonify({"msg": "Bad username or password"}), 401
        else:
            return jsonify({"msg": "Missing auth parameters"}), 401

        # Identity can be any data that is json serializable
        ret = {'access_token': create_access_token(identity=params['username'])}
        return jsonify(ret), 200
    else:
        return jsonify({"msg": "Missing auth"}), 401

# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify({'hello_from': current_user}), 200

if __name__ == '__main__':
    app.run()
