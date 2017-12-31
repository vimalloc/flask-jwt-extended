import datetime
import uuid

from calendar import timegm

import jwt
from werkzeug.security import safe_str_cmp

from flask_jwt_extended.exceptions import JWTDecodeError, CSRFError


def _create_csrf_token():
    return str(uuid.uuid4())


def _encode_jwt(additional_token_data, expires_delta, secret, algorithm):
    uid = str(uuid.uuid4())
    now = datetime.datetime.utcnow()
    token_data = {
        'iat': now,
        'nbf': now,
        'jti': uid,
    }
    # If expires_delta is False, the JWT should never expire
    # and the 'exp' claim is not set.
    if expires_delta:
        token_data['exp'] = now + expires_delta
    token_data.update(additional_token_data)
    encoded_token = jwt.encode(token_data, secret, algorithm).decode('utf-8')
    return encoded_token


def encode_access_token(identity, secret, algorithm, expires_delta, fresh,
                        user_claims, csrf, identity_claim_key, user_claims_key):
    """
    Creates a new encoded (utf-8) access token.

    :param identity: Identifier for who this token is for (ex, username). This
                     data must be json serializable
    :param secret: Secret key to encode the JWT with
    :param algorithm: Which algorithm to encode this JWT with
    :param expires_delta: How far in the future this token should expire
                          (set to False to disable expiration)
    :type expires_delta: datetime.timedelta or False
    :param fresh: If this should be a 'fresh' token or not. If a
                  datetime.timedelta is given this will indicate how long this
                  token will remain fresh.
    :param user_claims: Custom claims to include in this token. This data must
                        be json serializable
    :param csrf: Whether to include a csrf double submit claim in this token
                 (boolean)
    :param identity_claim_key: Which key should be used to store the identity
    :param user_claims_key: Which key should be used to store the user claims
    :return: Encoded access token
    """

    if isinstance(fresh, datetime.timedelta):
        now = datetime.datetime.utcnow()
        fresh = timegm((now + fresh).utctimetuple())

    token_data = {
        identity_claim_key: identity,
        'fresh': fresh,
        'type': 'access',
    }

    # Don't add extra data to the token if user_claims is empty.
    if user_claims:
        token_data[user_claims_key] = user_claims

    if csrf:
        token_data['csrf'] = _create_csrf_token()
    return _encode_jwt(token_data, expires_delta, secret, algorithm)


def encode_refresh_token(identity, secret, algorithm, expires_delta, csrf,
                         identity_claim_key):
    """
    Creates a new encoded (utf-8) refresh token.

    :param identity: Some identifier used to identify the owner of this token
    :param secret: Secret key to encode the JWT with
    :param algorithm: Which algorithm to use for the toek
    :param expires_delta: How far in the future this token should expire
                          (set to False to disable expiration)
    :type expires_delta: datetime.timedelta or False
    :param csrf: Whether to include a csrf double submit claim in this token
                 (boolean)
    :param identity_claim_key: Which key should be used to store the identity
    :return: Encoded refresh token
    """
    token_data = {
        identity_claim_key: identity,
        'type': 'refresh',
    }
    if csrf:
        token_data['csrf'] = _create_csrf_token()
    return _encode_jwt(token_data, expires_delta, secret, algorithm)


def decode_jwt(encoded_token, secret, algorithm, identity_claim_key,
               user_claims_key, csrf_value=None):
    """
    Decodes an encoded JWT

    :param encoded_token: The encoded JWT string to decode
    :param secret: Secret key used to encode the JWT
    :param algorithm: Algorithm used to encode the JWT
    :param identity_claim_key: expected key that contains the identity
    :param user_claims_key: expected key that contains the user claims
    :param csrf_value: Expected double submit csrf value
    :return: Dictionary containing contents of the JWT
    """
    # This call verifies the ext, iat, and nbf claims
    data = jwt.decode(encoded_token, secret, algorithms=[algorithm])

    # Make sure that any custom claims we expect in the token are present
    if 'jti' not in data:
        raise JWTDecodeError("Missing claim: jti")
    if identity_claim_key not in data:
        raise JWTDecodeError("Missing claim: {}".format(identity_claim_key))
    if 'type' not in data or data['type'] not in ('refresh', 'access'):
        raise JWTDecodeError("Missing or invalid claim: type")
    if data['type'] == 'access':
        if 'fresh' not in data:
            raise JWTDecodeError("Missing claim: fresh")
        if user_claims_key not in data:
            data[user_claims_key] = {}
    if csrf_value:
        if 'csrf' not in data:
            raise JWTDecodeError("Missing claim: csrf")
        if not safe_str_cmp(data['csrf'], csrf_value):
            raise CSRFError("CSRF double submit tokens do not match")
    return data
