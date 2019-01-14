from flask import Flask, jsonify
from flask_restful import Api
import requests
import json
from jwt.algorithms import RSAAlgorithm
from functools import wraps
from flask_jwt_extended import (
    JWTManager, verify_jwt_in_request, get_raw_jwt, current_user
)
import config


# Setup Flask Server
app = Flask(__name__)
app.config.from_object(config.Config)
api = Api(app)

# ==== SETUP
# Set OIDC entries for auto-discovery
# Naming of 4 key input variables borrowed from Kubernetes (https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
# This was tested with Red Hat's https://www.keycloak.org/ but should work with any OIDC provider like Auth0, Octa, Google, Microsoft etc.

# Issuer + Realm
OIDC_ISSUER_URL = 'https://my-identity-server.example/auth/realms/master'

# Client ID (Audience)
OIDC_CLIENT_ID = 'example.my-identity-server'

# Token variable holding unique username
OIDC_USERNAME_CLAIM = 'email'

# Token list variable holding groups that user belongs to (for role-based-access-control)
# idea here is to have few but could be hundreds of groups, based on which groups user belongs to, grants them access to various endpoints
# in identity server this is usually mapped directly to ldap, so ldap group membership defines which endpoints user can access
# https://www.keycloak.org/docs/latest/server_admin/index.html#_ldap_mappers, but remember groups don't have to come from ldap
# group mapper was setup for flat group structure not to include any prefixes so if you have to do that, please update code in group_required method
OIDC_GROUPS_CLAIM = 'groups'

# ==== END OF SETUP


# Helper Methods
def urljoin(*args):
    """
    Joins given arguments into an url. Trailing but not leading slashes are
    stripped for each argument.
    """

    return "/".join(map(lambda x: str(x).rstrip('/'), args))


def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        return fn(*args, **kwargs)
    return wrapper


def group_required(group=''):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # standard flask_jwt_extended token verifications
            verify_jwt_in_request()

            # custom group membership verification
            groups = get_raw_jwt()[OIDC_GROUPS_CLAIM]
            if group not in groups:
                return jsonify({'result': "user not in group required to access this endpoint"}), 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# Setup Token Verification
# force use of RS265
app.config['JWT_ALGORITHM'] = 'RS256'

# retrieve master openid-configuration endpoint for issuer realm
oidc_config = requests.get(urljoin(OIDC_ISSUER_URL, '.well-known/openid-configuration'), verify=False).json()

# retrieve data from jwks_uri endpoint
oidc_jwks_uri = requests.get(oidc_config['jwks_uri'], verify=False).json()

# retrieve first jwk entry from jwks_uri endpoint and use it to construct the RSA public key
app.config['JWT_PUBLIC_KEY'] = RSAAlgorithm.from_jwk(json.dumps(oidc_jwks_uri['keys'][0]))

# audience is oidc client id (can be array starting https://github.com/vimalloc/flask-jwt-extended/issues/219)
app.config['JWT_DECODE_AUDIENCE'] = OIDC_CLIENT_ID

# name of token entry that will become distinct flask identity username
app.config['JWT_IDENTITY_CLAIM'] = OIDC_USERNAME_CLAIM
jwt = JWTManager(app)


# TEST ENDPOINTS
@app.route('/anonymous', methods=['GET'])
def get_anonymous():
    return jsonify({'result': "anonymous ok"}), 200


@app.route('/token-protected', methods=['GET'])
@token_required
def get_protected_by_token():
    return jsonify({'result': "protected by token ok"}), 200


@app.route('/group-protected', methods=['GET'])
@group_required('api-access')  # currently one, could be one of or multiple required depending on your needs
def get_protected_by_group():
    return jsonify({'result': "protected by token AND group membership ok"},
                   {'user': current_user.username}
                   ), 200


# Identity User Class
class User:
    username = None

    def __init__(self):
        pass


# User Class to get you started
# Identity holds whatever variable in token you point at JWT_IDENTITY_CLAIM
# good place to construct identity from token and other places, it is then available in method through current_user.<property>
@jwt.user_loader_callback_loader
def user_loader_callback(identity):
    u = User()
    u.username = identity
    return u


app.run(host='0.0.0.0')


