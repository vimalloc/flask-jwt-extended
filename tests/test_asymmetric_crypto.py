import pytest
from flask import Flask, jsonify

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

RSA_PRIVATE = """
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDN+p9a9oMyqRzkae8yLdJcEK0O0WesH6JiMz+KDrpUwAoAM/KP
DnxFnROJDSBHyHEmPVn5x8GqV5lQ9+6l97jdEEcPo6wkshycM82fgcxOmvtAy4Uo
xq/AeplYqplhcUTGVuo4ZldOLmN8ksGmzhWpsOdT0bkYipHCn5sWZxd21QIDAQAB
AoGBAMJ0++KVXXEDZMpjFDWsOq898xNNMHG3/8ZzmWXN161RC1/7qt/RjhLuYtX9
NV9vZRrzyrDcHAKj5pMhLgUzpColKzvdG2vKCldUs2b0c8HEGmjsmpmgoI1Tdf9D
G1QK+q9pKHlbj/MLr4vZPX6xEwAFeqRKlzL30JPD+O6mOXs1AkEA8UDzfadH1Y+H
bcNN2COvCqzqJMwLNRMXHDmUsjHfR2gtzk6D5dDyEaL+O4FLiQCaNXGWWoDTy/HJ
Clh1Z0+KYwJBANqRtJ+RvdgHMq0Yd45MMyy0ODGr1B3PoRbUK8EdXpyUNMi1g3iJ
tXMbLywNkTfcEXZTlbbkVYwrEl6P2N1r42cCQQDb9UQLBEFSTRJE2RRYQ/CL4yt3
cTGmqkkfyr/v19ii2jEpMBzBo8eQnPL+fdvIhWwT3gQfb+WqxD9v10bzcmnRAkEA
mzTgeHd7wg3KdJRtQYTmyhXn2Y3VAJ5SG+3qbCW466NqoCQVCeFwEh75rmSr/Giv
lcDhDZCzFuf3EWNAcmuMfQJARsWfM6q7v2p6vkYLLJ7+VvIwookkr6wymF5Zgb9d
E6oTM2EeUPSyyrj5IdsU2JCNBH1m3JnUflz8p8/NYCoOZg==
-----END RSA PRIVATE KEY-----
"""

RSA_PUBLIC = """
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM36n1r2gzKpHORp7zIt0lwQrQ7RZ6wfomIzP4oOulTACgAz8o8OfEWd
E4kNIEfIcSY9WfnHwapXmVD37qX3uN0QRw+jrCSyHJwzzZ+BzE6a+0DLhSjGr8B6
mViqmWFxRMZW6jhmV04uY3ySwabOFamw51PRuRiKkcKfmxZnF3bVAgMBAAE=
-----END RSA PUBLIC KEY-----
"""


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    app.config['JWT_PUBLIC_KEY'] = RSA_PUBLIC
    app.config['JWT_PRIVATE_KEY'] = RSA_PRIVATE
    JWTManager(app)

    @app.route('/protected', methods=['GET'])
    @jwt_required
    def protected():
        return jsonify(foo='bar')

    return app


def test_asymmetric_cropto(app):
    test_client = app.test_client()

    with app.test_request_context():
        hs256_token = create_access_token('username')
        app.config['JWT_ALGORITHM'] = 'RS256'
        rs256_token = create_access_token('username')

    # Insure the symmetric token does not work now
    access_headers = {'Authorization': 'Bearer {}'.format(hs256_token)}
    response = test_client.get('/protected', headers=access_headers)
    assert response.status_code == 422
    assert response.get_json() == {'msg': 'The specified alg value is not allowed'}

    # Insure the asymmetric token does work
    access_headers = {'Authorization': 'Bearer {}'.format(rs256_token)}
    response = test_client.get('/protected', headers=access_headers)
    assert response.status_code == 200
    assert response.get_json() == {'foo': 'bar'}
