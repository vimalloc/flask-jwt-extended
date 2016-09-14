import uuid
import datetime

import json

from functools import wraps

import jwt
from werkzeug.local import LocalProxy
from flask import Flask, request, jsonify

# TODO read this whole page
# Per http://flask.pocoo.org/docs/0.11/extensiondev/
#
# Find the stack on which we want to store the database connection.
# Starting with Flask 0.9, the _app_ctx_stack is the correct one,
# before that we need to use the _request_ctx_stack.
try:
    from flask import _app_ctx_stack as ctx_stack
except ImportError:
    from flask import _request_ctx_stack as ctx_stack


# TODO figure out what doc im using (pydoc?) and test it


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


class JWTEncodeError(JWTExtendedException):
    pass


class InvalidHeaderError(JWTExtendedException):
    pass


def _get_identity():
    return getattr(ctx_stack.top, 'jwt_identity', None)
jwt_identity = LocalProxy(lambda: _get_identity())


def _get_user_claims():
    return getattr(ctx_stack.top, 'jwt_user_claims', {})
jwt_user_claims = LocalProxy(lambda: _get_user_claims())


# TODO provide callback function to insert custom claims data into the jwt
# TODO add newly created tokens to 'something' so they can be blacklisted later.
#      Should this be only refresh tokens, or access tokens to? Or an option for either
# TODO callback method for jwt_required failed (See
#      https://github.com/maxcountryman/flask-login/blob/master/flask_login/utils.py#L221)
def _encode_access_token(identity, secret, fresh, algorithm, user_claims=None):
    """
    Creates a new access token.

    :param identity: Some identifier of who this client is (most common would be a client id)
    :param secret: Secret key to encode the JWT with
    :param fresh: If this should be a 'fresh' token or not
    :param algorithm: Which algorithm to use for the toek
    :return: Encoded JWT
    """
    # Verify that all of our custom data we are encoding is what we expect
    if user_claims is None:
        user_claims = {}
    if not isinstance(user_claims, dict):
        raise JWTEncodeError('user_claims must be a dict')
    if not isinstance(fresh, bool):
        raise JWTEncodeError('fresh must be a bool')
    try:
        json.dumps(user_claims)
    except Exception as e:
        raise JWTEncodeError('Error json serializing user_claims: {}'.format(str(e)))

    # Encode and return the jwt
    now = datetime.datetime.utcnow()
    token_data = {
        'exp': now + ACCESS_TOKEN_EXPIRE_DELTA,
        'iat': now,
        'nbf': now,
        'jti': str(uuid.uuid4()),
        'identity': identity,
        'fresh': fresh,
        'type': 'access',
        'user_claims': user_claims,
    }
    return jwt.encode(token_data, secret, algorithm).decode('utf-8')


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
        data = jwt.decode(token, secret, algorithm=algorithm)
    except jwt.InvalidTokenError as e:
        raise JWTDecodeError(str(e))

    # ext, iat, and nbf are all verified by pyjwt. We just need to make sure
    # that the custom claims we put in the token are present
    if 'jti' not in data or not isinstance(data['jti'], str):
        raise JWTDecodeError("Missing or invalid claim: jti")
    if 'identity' not in data:
        raise JWTDecodeError("Missing claim: identity")
    if 'type' not in data or data['type'] not in ('refresh', 'access'):
        raise JWTDecodeError("Missing or invalid claim: type")
    if data['type'] == 'access':
        if 'fresh' not in data or not isinstance(data['fresh'], bool):
            raise JWTDecodeError("Missing or invalid claim: fresh")
        if 'user_claims' not in data or not isinstance(data['user_claims'], dict):
            raise JWTDecodeError("Missing or invalid claim: user_claims")
    return data


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


def add_user_claims(identity):
    """
    Example of adding custom user claims to the jwt
    """
    return {
        'foo': 'bar',
        'ip': request.remote_addr
    }


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
            # Save the jwt take in flask.g so that it can be accessed later by
            # the various endpoints that is using this decorator
            ctx_stack.top.jwt_identity = jwt_data['identity']
            ctx_stack.top.jwt_user_claims = jwt_data['user_claims']
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
            # Save the jwt take in flask.g so that it can be accessed later by
            # the various endpoints that is using this decorator
            ctx_stack.top.jwt_identity = jwt_data['identity']
            ctx_stack.top.jwt_user_claims = jwt_data['user_claims']
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
        user_claims = add_user_claims(username)
        access_token = _encode_access_token(username, SECRET, False, 'HS256',
                                            user_claims=user_claims)
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
    user_claims = add_user_claims(jwt_data['identity'])
    access_token = _encode_access_token(jwt_data['identity'], SECRET, False, 'HS256',
                                        user_claims=user_claims)
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
        user_claims = add_user_claims(username)
        access_token = _encode_access_token(username, SECRET, False, 'HS256',
                                            user_claims=user_claims)
        ret = {
            'access_token': access_token,
        }
        return jsonify(ret), 200


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
