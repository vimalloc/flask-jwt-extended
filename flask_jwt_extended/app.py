import uuid
import datetime

from functools import wraps

import jwt
from flask import Flask, request, jsonify

# TODO figure out what doc im usign (pydoc?) and test it


# Options, should be moved to app.config
ACCESS_TOKEN_EXPIRE_DELTA = datetime.timedelta(minutes=5)
REFRESH_TOKEN_EXPIRE_DELTA = datetime.timedelta(days=7)
SECRET = 'super-secret-key'
# Blacklist enabled
# blacklist options (simplekv)
# blacklist check requests (all, refresh_token, none)


# Exceptions for flask-jwt-extended exceptions
class JWTExtendedException(Exception):
    pass


class JWTDecodeError(JWTExtendedException):
    pass


class InvalidHeaderError(JWTExtendedException):
    pass


# TODO access JWT contents in function (flask.g I think)
# TODO required jwt claims verification (how to deal with fresh? Different claims
#      for access/refresh tokens? Or just set fresh to false on the refresh token
# TODO add newly created tokens to 'something' so they can be blacklisted later.
#      Should this be only refresh tokens, or access tokens to? Or an option for either
# TODO add custom data to token (username, ip, etc)
# TODO callback method for jwt_required failed (See
#      https://github.com/maxcountryman/flask-login/blob/master/flask_login/utils.py#L221)
def _encode_access_token(identity, secret, fresh, algorithm):
    """
    Creates a new access token.

    :param identity: Some identifier of who this client is (most common would be a client id)
    :param secret: Secret key to encode the JWT with
    :param fresh: If this should be a 'fresh' token or not
    :param algorithm: Which algorithm to use for the toek
    :return: Encoded JWT
    """
    now = datetime.datetime.utcnow()
    token_data = {
        'exp': now + ACCESS_TOKEN_EXPIRE_DELTA,
        'iat': now,
        'nbf': now,
        'jti': str(uuid.uuid4()),
        'identity': identity,
        'fresh': fresh,
        'type': 'access',
    }
    byte_str = jwt.encode(token_data, secret, algorithm)
    return byte_str.decode('utf-8')


def _encode_refresh_token(identity, secret, algorithm):
    """
    Creates a new refresh token, which can be used to create subsequent access
    tokens.

    :param identity: TODO - not sure I want this. flask-jwt leads to unnecessary db calls on every call
    :param secret: Secret key to encode the JWT with
    :param algorithm: Which algorithm to use for the toek
    :return: Encoded JWT
    """
    now = datetime.datetime.utcnow()
    token_data = {
        'exp': now + REFRESH_TOKEN_EXPIRE_DELTA,
        'iat': now,
        'nbf': now,
        'jti': str(uuid.uuid4()),
        'identity': identity,
        'type': 'refresh',
    }
    byte_str = jwt.encode(token_data, secret, algorithm)
    return byte_str.decode('utf-8')


def _decode_jwt(token, secret, algorithm):
    """
    Decodes an encoded JWT

    :param token: The encoded JWT string to decode
    :param secret: Secret key used to encode the JWT
    :param algorithm: Algorithm used to encode the JWT
    :return: Dictionary containing contents of the JWT
    """
    try:
        return jwt.decode(token, secret, algorithm=algorithm)
    except jwt.InvalidTokenError as e:
        raise JWTDecodeError(str(e))


def _verify_jwt_from_request():
    """
    Returns the encoded JWT string from the request

    :return: Encoded jwt string, or None if it does not exist
    """
    # Verify we have the auth header
    auth_header = request.headers.get('Authorization', None)
    if not auth_header:
        raise InvalidHeaderError("Missing Authorization Header")

    # Make sure the header is valid
    parts = auth_header.split()
    if parts[0] != 'Bearer':
        msg = "Badly formatted authorization header. Should be 'Bearer <JWT>'"
        raise InvalidHeaderError(msg)
    elif len(parts) != 2:
        msg = "Badly formatted authorization header. Should be 'Bearer <JWT>'"
        raise InvalidHeaderError(msg)

    # Return the token (raises a JWTDecodeError if decoding fails)
    token = parts[1]
    return _decode_jwt(token, SECRET, 'HS256')


def jwt_required(fn):
    """
    If you decorate a vew with this, it will ensure that the requester has a valid
    JWT before calling the actual view. This does not check the freshness of the
    token. (TODO href to those docs)

    See also: fresh_jwt_required()

    :param fn: The view function to decorate
    :type fn: function
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            jwt_data = _verify_jwt_from_request()
        except InvalidHeaderError as e:
            return jsonify({'msg': str(e)}), 422
        except JWTDecodeError as e:
            return jsonify({'msg': str(e)}), 401

        if jwt_data['type'] != 'access':
            return jsonify({'msg': 'Only access tokens can access this endpoint'}), 401
        else:
            return fn(*args, **kwargs)
    return wrapper


def fresh_jwt_required(fn):
    """
    If you decorate a vew with this, it will ensure that the requester has a valid
    JWT before calling the actual view.

    TODO docs about freshness and callbacks

    See also: jwt_required()

    :param fn: The view function to decorate
    :type fn: function
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            jwt_data = _verify_jwt_from_request()
        except InvalidHeaderError as e:
            return jsonify({'msg': str(e)}), 422
        except JWTDecodeError as e:
            return jsonify({'msg': str(e)}), 401

        if jwt_data['type'] != 'access':
            return jsonify({'msg': 'Only access tokens can access this endpoint'}), 401
        elif not jwt_data['fresh']:
            return jsonify({'msg': 'TODO - need fresh jwt'}), 401
        else:
            return fn(*args, **kwargs)
    return wrapper


# Flask test stuff
app = Flask(__name__)
app.debug = True


def _check_username_password(username, password):
    if username == 'test' and password == 'test':
        return True
    else:
        return False


@app.route('/auth/login', methods=['POST'])
def jwt_auth():
    username = request.json.get('username', None)
    if not username:
        return jsonify({'msg': 'TODO make callback - username not in request'}), 422
    password = request.json.get('password', None)
    if not password:
        return jsonify({'msg': 'TODO make callback - password not in request'}), 422

    if not _check_username_password(username, password):
        return jsonify({'msg': 'Invalid username or password'}), 401
    else:
        access_token = _encode_access_token(username, SECRET, True, 'HS256')
        refresh_token = _encode_refresh_token(username, SECRET, 'HS256')
        ret = {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
        return jsonify(ret), 200


@app.route('/auth/refresh_login', methods=['POST'])
def jwt_refresh():
    # get the token
    try:
        jwt_data = _verify_jwt_from_request()
    except InvalidHeaderError as e:
        return jsonify({'msg': str(e)}), 422
    except JWTDecodeError as e:
        return jsonify({'msg': str(e)}), 401

    # verify this is a refresh token
    if jwt_data['type'] != 'refresh':
        return jsonify({'msg': 'Only refresh tokens can access this endpoint'}), 401

    # Send the caller a new access token
    access_token = _encode_access_token(jwt_data['identity'], SECRET, False, 'HS256')
    ret = {'access_token': access_token}
    return jsonify(ret), 200


@app.route('/auth/fresh_login', methods=['POST'])
def jwt_fresh_login():
    # Create a new access token only (no refresh token) that has fresh set to true
    username = request.json.get('username', None)
    if not username:
        return jsonify({'msg': 'TODO make callback - username not in request'}), 422
    password = request.json.get('password', None)
    if not password:
        return jsonify({'msg': 'TODO make callback - password not in request'}), 422

    if not _check_username_password(username, password):
        return jsonify({'msg': 'Invalid username or password'}), 401
    else:
        access_token = _encode_access_token(username, SECRET, True, 'HS256')
        ret = {
            'access_token': access_token,
        }
        return jsonify(ret), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def non_fresh_protected():
    return jsonify({'msg': 'hello world'})


@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def fresh_protected():
    return jsonify({'msg': 'hello world fresh'})


if __name__ == '__main__':
    app.run()
