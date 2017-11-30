import jwt
import pytest
from datetime import timedelta

from flask import Flask
from jwt import ExpiredSignatureError

from flask_jwt_extended import (
    JWTManager, create_access_token, decode_token, create_refresh_token,
    get_jti
)
from flask_jwt_extended.config import config
from flask_jwt_extended.exceptions import JWTDecodeError
from tests.utils import get_jwt_manager, encode_token


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'change_me'
    app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True
    JWTManager(app)
    return app


@pytest.fixture(scope='function')
def default_access_token(app):
    with app.test_request_context():
        return {
            'jti': '1234',
            config.identity_claim_key: 'username',
            'type': 'access',
            'fresh': True,
            'csrf': 'abcd'
        }


@pytest.mark.parametrize("user_loader_return", [{}, None])
def test_no_user_claims(app, user_loader_return):
    jwtM = get_jwt_manager(app)

    @jwtM.user_claims_loader
    def empty_user_loader_return(identity):
        return user_loader_return

    # Identity should not be in the actual token, but should be in the data
    # returned via the decode_token call
    with app.test_request_context():
        token = create_access_token('username')
        pure_decoded = jwt.decode(token, config.decode_key, algorithms=[config.algorithm])
        assert config.user_claims_key not in pure_decoded
        extension_decoded = decode_token(token)
        assert config.user_claims_key in extension_decoded


@pytest.mark.parametrize("missing_claim", ['jti', 'type', 'identity', 'fresh', 'csrf'])
def test_missing_jti_claim(app, default_access_token, missing_claim):
    del default_access_token[missing_claim]
    missing_jwt_token = encode_token(app, default_access_token)

    with pytest.raises(JWTDecodeError):
        with app.test_request_context():
            decode_token(missing_jwt_token, csrf_value='abcd')


def test_bad_token_type(app, default_access_token):
    default_access_token['type'] = 'banana'
    bad_type_token = encode_token(app, default_access_token)

    with pytest.raises(JWTDecodeError):
        with app.test_request_context():
            decode_token(bad_type_token)


def test_expired_token(app):
    with app.test_request_context():
        delta = timedelta(minutes=-5)
        access_token = create_access_token('username', expires_delta=delta)
        refresh_token = create_refresh_token('username', expires_delta=delta)
        with pytest.raises(ExpiredSignatureError):
            decode_token(access_token)
        with pytest.raises(ExpiredSignatureError):
            decode_token(refresh_token)


def test_alternate_identity_claim(app, default_access_token):
    app.config['JWT_IDENTITY_CLAIM'] = 'sub'

    # Insure decoding fails if the claim isn't there
    token = encode_token(app, default_access_token)
    with pytest.raises(JWTDecodeError):
        with app.test_request_context():
            decode_token(token)

    # Insure the claim exists in the decoded jwt
    del default_access_token['identity']
    default_access_token['sub'] = 'username'
    token = encode_token(app, default_access_token)
    with app.test_request_context():
        decoded = decode_token(token)
        assert 'sub' in decoded
        assert 'identity' not in decoded


def test_get_jti(app, default_access_token):
    token = encode_token(app, default_access_token)

    with app.test_request_context():
        assert default_access_token['jti'] == get_jti(token)
