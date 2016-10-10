from flask import Flask, jsonify, request

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jwt_identity,\
    set_access_cookies, set_refresh_cookie


app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


# Configure application to store JWTs in cookies
app.config['JWT_TOKEN_LOCATION'] = 'cookies'
app.config['JWT_COOKIE_SECURE'] = False  # In prod this should likely be True

# Set the cookie paths, so that you are only sending your access token cookie
# to the access endpoints, and only sending your refresh token to the refresh
# endpoint.
app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'

# Enable csrf double submit protection. Check out this for a simple overview
# of what this is: http://stackoverflow.com/a/37396572/272689.
app.config['JWT_COOKIE_CSRF_PROTECT'] = True


# Now, whenever you make a request to a protected endpoint, you will need to
# send in the access or refresh JWT via a cookie, as well as a custom header
# which has the same csrf token that is in the cookie. You cannot access the
# csrf token from the JWT, as httponly is set to true (and javascript thus
# cannot see it), but you can get the JWT from a secondary cookie (that only
# javascript on your site can access), and thus verify a csrf attack isn't
# happening.
#
# You can modify the cookie name, csrf cookie name, and csrf header name via
# various app.config options. Check the options page for details.


@app.route('/token/auth', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({'login': False}), 401

    # Create the tokens we will be sending back to the user
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    # Set the JWTs and the CSRF double submit protection cookies in this response
    resp = jsonify({'login': True})
    set_access_cookies(resp, access_token)
    set_refresh_cookie(resp, refresh_token)
    return resp, 200


@app.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # Create the new access token
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    # Set the access JWT and CSRF double submit protection cookies in this response
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    return resp, 200


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
