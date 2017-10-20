import datetime
import uuid

import jwt

from flask_jwt_extended.exceptions import JWTDecodeError
from flask_jwt_extended.config import config


def _create_csrf_token():
    return str(uuid.uuid4())


def _encode_jwt(additional_token_data, expires_delta, secret, algorithm):
    uid = str(uuid.uuid4())
    now = datetime.datetime.utcnow()
    token_data = {
        'exp': now + expires_delta,
        'iat': now,
        'nbf': now,
        'jti': uid,
    }
    token_data.update(additional_token_data)
    encoded_token = jwt.encode(token_data, secret, algorithm).decode('utf-8')
    return encoded_token


def encode_access_token(identity, secret, algorithm, expires_delta, fresh,
                        user_claims, csrf, identity_claim):
    """
    Creates a new encoded (utf-8) access token.

    :param identity: Identifier for who this token is for (ex, username). This
                     data must be json serializable
    :param secret: Secret key to encode the JWT with
    :param algorithm: Which algorithm to encode this JWT with
    :param expires_delta: How far in the future this token should expire
                               (datetime.timedelta)
    :param fresh: If this should be a 'fresh' token or not
    :param user_claims: Custom claims to include in this token. This data must
                        be json serializable
    :param csrf: Whether to include a csrf double submit claim in this token
                 (boolean)
    :param identity_claim: Which claim should be used to store the identity in
    :return: Encoded access token
    """
    # Create the jwt
    token_data = {
        identity_claim: identity,
        'fresh': fresh,
        'type': 'access',
    }

    # Add `user_claims` only is not empty or None.
    if user_claims:
        token_data[config.user_claims] = user_claims

    if csrf:
        token_data['csrf'] = _create_csrf_token()
    return _encode_jwt(token_data, expires_delta, secret, algorithm)


def encode_refresh_token(identity, secret, algorithm, expires_delta, csrf, identity_claim):
    """
    Creates a new encoded (utf-8) refresh token.

    :param identity: Some identifier used to identify the owner of this token
    :param secret: Secret key to encode the JWT with
    :param algorithm: Which algorithm to use for the toek
    :param expires_delta: How far in the future this token should expire
                               (datetime.timedelta)
    :param csrf: Whether to include a csrf double submit claim in this token
                 (boolean)
    :param identity_claim: Which claim should be used to store the identity in
    :return: Encoded refresh token
    """
    token_data = {
        identity_claim: identity,
        'type': 'refresh',
    }
    if csrf:
        token_data['csrf'] = _create_csrf_token()
    return _encode_jwt(token_data, expires_delta, secret, algorithm)


def decode_jwt(encoded_token, secret, algorithm, csrf, identity_claim):
    """
    Decodes an encoded JWT

    :param encoded_token: The encoded JWT string to decode
    :param secret: Secret key used to encode the JWT
    :param algorithm: Algorithm used to encode the JWT
    :param csrf: If this token is expected to have a CSRF double submit
                 value present (boolean)
    :param identity_claim: expected claim that is used to identify the subject
    :return: Dictionary containing contents of the JWT
    """
    # This call verifies the ext, iat, and nbf claims
    data = jwt.decode(encoded_token, secret, algorithms=[algorithm])

    # Make sure that any custom claims we expect in the token are present
    if 'jti' not in data:
        raise JWTDecodeError("Missing claim: jti")
    if identity_claim not in data:
        raise JWTDecodeError("Missing claim: {}".format(identity_claim))
    if 'type' not in data or data['type'] not in ('refresh', 'access'):
        raise JWTDecodeError("Missing or invalid claim: type")
    if data['type'] == 'access':
        if 'fresh' not in data:
            raise JWTDecodeError("Missing claim: fresh")
        if config.user_claims not in data:
            data[config.user_claims] = {}
    if csrf:
        if 'csrf' not in data:
            raise JWTDecodeError("Missing claim: csrf")
    return data
