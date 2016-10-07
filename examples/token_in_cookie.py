import binascii
import json
import os

from flask import Flask, jsonify, request
from flask import Response

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jwt_identity

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


# TODO add additional_claims as optional arg to create_token methods
# TODO config option to check for tokens in cookie instead of request headers (or both)
# TODO config option to do xsrf double submit verification on protected endpoints

def _create_xsrf_token():
    return binascii.hexlify(os.urandom(60))


@app.route('/token/auth', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # Create the x-xsrf-token we will use for CSRF double submit verification
    x_xsrf_access_token = _create_xsrf_token()
    x_xsrf_refresh_token = _create_xsrf_token()
    access_claims = {'X-XSRF-TOKEN': x_xsrf_access_token}
    refresh_claims = {'X-XSRF-TOKEN': x_xsrf_refresh_token}

    # Create the access and refresh tokens with the x-xsrf-token included
    access_token = create_access_token(identity=username,
                                       additional_claims=access_claims)
    refresh_token = create_refresh_token(identity=username,
                                         additional_claims=refresh_claims)

    # Create the response we will send back to the caller.
    data = json.dumps({'login': True})
    resp = Response(response=data, status=200, mimetype="application/json")

    # Save the access and refresh tokens in a cookie with this request.
    # The secure option insures that the cookie is only sent over https,
    # httponly makes it so javascript cannot access this cookie, and prevents
    # XSS attacks (we are still vulnerable to CSRF though), and path says to
    # only send this cookie if it matches the path. Using the path, we can have
    # access tokens only sent when we go to protected endpoints, and refresh
    # tokens only sent when we go to the refresh endpoint
    resp.set_cookie('access_token',
                    value=access_token,
                    secure=True,
                    httponly=True,
                    path='/api/')
    resp.set_cookie('refresh_token',
                    value=refresh_token,
                    secure=True,
                    httponly=True,
                    path='/token/refresh')

    # Set the X-XSRF-TOKEN in a not httponly token (which can be accessed by
    # javascript, but only by javascript running on this domain). From here on
    # out, we will need to set the X-XSRF-TOKEN header for each request, getting
    # the xsrf token from this cookie. On the backend, we will be verifying the
    # xsrf token in the header matches the xsrf token in the JWT. The end result
    # of this is that attackers will not be able to perform CSRF attacks, as they
    # could send the JWT back with the request, but without the additional xsrf
    # header they will not get accepted, and they cannot access the xsrf token
    # as this cookie can only be accessed by javascript running from the same
    # domain (and the JWT is httponly and cannot be accessed by any javascript).
    # Additionally, the users access and refresh token can not be stolen via
    # XSS (again, because they are httponly), but XSS attacks could still be
    # used to perform actions for a user without stealing their cookie.
    resp.set_cookie('x_xsrf_access_token',
                    value=x_xsrf_access_token,
                    secure=True,
                    httponly=False,
                    path='/api/')
    resp.set_cookie('x_xsrf_refresh_token',
                    value=x_xsrf_refresh_token,
                    secure=True,
                    httponly=False,
                    path='/token/refresh')

    return resp


@app.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # New xsrf token to use with the new jwt
    x_xsrf_token = _create_xsrf_token()

    # Create the new jwt
    claims = {'X-XSRF-TOKEN': x_xsrf_token}
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user, additional_claims=claims)

    # Create the respons to send back to the caller
    data = json.dumps({'refresh': True})
    resp = Response(response=data, status=200, mimetype="application/json")

    # Set the JWT and XSRF TOKEN in the cookie with the same options and
    # security that we used for the original access token
    resp.set_cookie('access_token',
                    value=access_token,
                    secure=True,
                    httponly=True,
                    path='/api/')
    resp.set_cookie('x_xsrf_access_token',
                    value=x_xsrf_token,
                    secure=True,
                    httponly=False,
                    path='/api/')

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
