from flask import Flask, jsonify, request

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jwt_identity,\
    set_access_cookies, set_refresh_cookie


# NOTE: This is being actively worked on, and is not complete yet. At present,
#       this code will not work! It should be rolled out next week sometime


app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


# Configure application to store jwts in cookies with double submit csrf protection
app.config['JWT_TOKEN_LOCATION'] = 'cookie'
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_SECURE'] = True

app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'

app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token_cookie'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'

app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'x_xsrf_access_token'
app.config['JWT_REFRESH_CSRF_COOKIE_NAME'] = 'x_xsrf_refresh_token'


@app.route('/token/auth', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # Create the tokens we will be sending back to the user
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    # Set the JWTs and the CSRF double submit protection cookies in this response
    resp = jsonify({'login': True}), 200
    set_access_cookies(resp, access_token)
    set_refresh_cookie(resp, refresh_token)
    return resp


@app.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # Create the new access token
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    # Set the access JWT and CSRF double submit protection cookies in this response
    resp = jsonify({'refresh': True}), 200
    set_access_cookies(resp, access_token)
    return resp


# We do not need to make any changes here, all of the protected endpoints will
# function the exact same as they do when sending the jwt in via the authorization
# header instead of in a cookie
@app.route('/api/example', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200

if __name__ == '__main__':
    app.run()
