# Flask-JWT-Extended
Flask-JWT-Extended adds support for using JSON Web Tokens (JWT) to Flask for protecting views.

This has several optional features built it to make working with JSON Web Tokens
easier. These include:

* Support for adding custom claims to JSON Web Tokens
* [Refresh tokens] (https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
* Token freshness and separate view decorators to only allow fresh tokens
* Token revoking

# Installation
The easiest way to start working with this extension with pip:
```
pip install flask-jwt-extended
```

If you prefer to install from source, you can clone this repo and run
```
python setup.py install
```

# Usage
### Basic Usage
In its simplest form, there is not much to using flask_jwt_extended.
```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!

# Setup the Flask-JWT-Extended extension
jwt = JWTManager(app)


# Provide a method to create access tokens. The create_access_token() function
# is used to actually generate the token
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {'access_token': create_access_token(username)}
    return jsonify(ret), 200


# Protect a view with jwt_required, which requires a valid access token in the
# request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'}), 200

if __name__ == '__main__':
    app.run()
```

To access a **jwt_required** protected view, all we have to do is send an authorization
head with the request that include the token. The header looks like this:
```
Authorization: Bearer <access_token>
```

We can see this in action using CURL:
```
$ curl --write-out "%{http_code}\n"  http://localhost:5000/protected
{
  "msg": "Missing Authorization Header"
}
401

$ curl --write-out "%{http_code}\n" -H "Content-Type: application/json" -X POST -d '{"username":"test","password":"test"}' http://localhost:5000/login
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwianRpIjoiZjhmNDlmMjUtNTQ4OS00NmRjLTkyOWUtZTU2Y2QxOGZhNzRlIiwidXNlcl9jbGFpbXMiOnt9LCJuYmYiOjE0NzQ0NzQ3OTEsImlhdCI6MTQ3NDQ3NDc5MSwiaWRlbnRpdHkiOiJ0ZXN0IiwiZXhwIjoxNDc0NDc1NjkxLCJ0eXBlIjoiYWNjZXNzIn0.vCy0Sec61i9prcGIRRCbG8e9NV6_wFH2ICFgUGCLKpc"
}
200

$ export ACCESS="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwianRpIjoiZjhmNDlmMjUtNTQ4OS00NmRjLTkyOWUtZTU2Y2QxOGZhNzRlIiwidXNlcl9jbGFpbXMiOnt9LCJuYmYiOjE0NzQ0NzQ3OTEsImlhdCI6MTQ3NDQ3NDc5MSwiaWRlbnRpdHkiOiJ0ZXN0IiwiZXhwIjoxNDc0NDc1NjkxLCJ0eXBlIjoiYWNjZXNzIn0.vCy0Sec61i9prcGIRRCbG8e9NV6_wFH2ICFgUGCLKpc"

$ curl --write-out "%{http_code}\n" -H "Authorization: Bearer $ACCESS" http://localhost:5000/protected
{
  "hello": "world"
}
200
```

### Adding Custom Data (Claims) to the Access Token
You may want to store additional information in the access token. Perhaps you want
to save the access roles this user has so you can access them in the view functions
(without having to make a database call each time). This can be done with the
**user_claims_loader** decorator, and accessed later with the 'get_jwt_claims()'
method (in a protected endpoint).

```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    get_jwt_claims

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


# Using the user_claims_loader, we can specify a method that will be called
# when creating access tokens, and add these claims to the said token. This
# method is passed the identity of who the token is being created for, and
# must return data that is json serializable
@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    return {
        'hello': identity,
        'foo': ['bar', 'baz']
    }


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {'access_token': create_access_token(username)}
    return jsonify(ret), 200


# In a protected view, get the claims you added to the jwt with the
# get_jwt_claims() method
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    claims = get_jwt_claims()
    return jsonify({
        'hello_is': claims['hello'],
        'foo_is': claims['foo']
    }), 200

if __name__ == '__main__':
    app.run()
```

### Refresh Tokens
Flask-JWT-Extended supports [refresh tokens] (https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
out of the box. These are longer lived token which cannot access a jwt_required protected
endpoint, but can be used to create new access tokens once an old access token has expired.
By setting the access tokens to a shorter lifetime (see Options below), and utilizing
fresh tokens for critical views (see Fresh Tokens below) we can help reduce the
damage done if an access token is stolen. Here is an example of how you
might use them in your application:

```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jwt_identity

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # Use create_access_token() and create_refresh_token() to create our
    # access and refresh tokens
    ret = {
        'access_token': create_access_token(identity=username),
        'refresh_token': create_refresh_token(identity=username)
    }
    return jsonify(ret), 200


# The jwt_refresh_token_required decorator insures a valid refresh token is
# present in the request before calling this endpoint. We can use the
# get_jwt_identity() function to get the identity of the refresh toke, and use
# the create_access_token() function again to make a new access token for this
# identity.
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200

if __name__ == '__main__':
    app.run()
```

### Token Freshness
We have the idea of token freshness built into this extension. In a nutshell, you can
choose to mark some access tokens as fresh and others as non-fresh, and use the
**fresh_jwt_required** decorator to only allow fresh tokens to access some views.

This is useful for allowing fresh tokens to do some critical things (maybe change
a password, or complete an online purchase), but to deny those features to
non-fresh tokens without forcing them to re-authenticate. This still allows your
users to access any of the normal jwt_protected endpoints while using a non-fresh
token. Using these can lead to a more secure site, without creating a burden
on the users experiences by forcing them to re-authenticate all the time.

The provided API gives you the power to use the token freshness however you may
want to. A very natural way to do this would be to mark a token as fresh when they
first login, mark any tokens generated with the refresh token to as not fresh.
```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jwt_identity, \
    fresh_jwt_required

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


# Standard login endpoint. Will return a fresh access token and a refresh token
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # create_access_token supports an optional 'fresh' argument, which marks the
    # token as fresh or non-fresh accordingly. As we just verified their username
    # and password, we are going to mark the token as fresh here.
    ret = {
        'access_token': create_access_token(identity=username, fresh=True),
        'refresh_token': create_refresh_token(identity=username)
    }
    return jsonify(ret), 200


# Fresh login endpoint. This is designed to be used if we need to make a fresh
# token for a user (by verifying they have the correct username and password).
# Unlike the standard login endpoint, this will only return a new access token
# (so that we don't keep generating new refresh tokens, which defeats their point)
@app.route('/fresh-login', methods=['POST'])
def fresh_login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {'access_token': create_access_token(identity=username, fresh=True)}
    return jsonify(ret), 200


# Refresh token endpoint. This will generate a new access token from the refresh
# token, but will mark that access token as non-fresh (so that it cannot access
# any endpoint protected via the fresh_jwt_required decorator)
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user, fresh=False)
    }
    return jsonify(ret), 200


# Any valid jwt can access this endpoint
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200


# Only fresh jwts can access this endpoint
@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def protected_fresh():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200

if __name__ == '__main__':
    app.run()
```

### Changing Default Behaviors
We provide what we think are sensible behaviors when attempting to access a protected
endpoint. If the access token is not valid for any reason (missing, expired, tampered with,
etc) we will return json in the format of **{'msg': 'why accessing endpoint failed'}**
along with an appropriate http status code (generally 401 or 422). However, you may want
to customize what you returned in these situations. We can do that with the jwt_manager
**_loader** functions.
```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


# Use the expired_token_loader to call this function whenever an expired but
# otherwise valid access token tries to access an endpoint
@jwt.expired_token_loader
def my_expired_token_callback():
    return jsonify({
        'status': 401,
        'sub_status': 101,
        'msg': 'The token has expired'
    }), 200


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {'access_token': create_access_token(username)}
    return jsonify(ret), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'}), 200

if __name__ == '__main__':
    app.run()
```

The available loader functions are:

| Decorator | Description | Callback Function Arguments |
| --------- | ----------- | --------------------------- |
|expired_token_loader | Function to call when an expired token accesses a protected view | None |
|invalid_token_loader | Function to call when an invalid token accesses a protected view | Takes one argument, which is an error string of why it is invalid|
|unauthorized_loader | Function to call when a request with no JWT accesses a protected view | None|
|needs_fresh_token_loader | Function to call when a non-fresh token access a **fresh_jwt_required** view | None |
|revoked_token_loader | Function to call when a revoked token accesses a protected view | None |

### Options
You can change many options for how this extension works via
```python
app.config[OPTION_NAME] = new_options
```
The available options are:

| Name   | Description | Options | Default|
| ------ | ----------- | ------- | ------ |
|JWT_ACCESS_TOKEN_EXPIRES | How long an access token should live | datetime.timedelta | 15 minutes|
|JWT_REFRESH_TOKEN_EXPIRES | How long a refresh token should live | datetime.timedelta | 30 days |
|JWT_ALGORITHM | Which algorithm to use with the JWT. | [See here] (https://pyjwt.readthedocs.io/en/latest/algorithms.html) | HS256 |
|JWT_BLACKLIST_ENABLED | If token blacklist/revoking should be enabled | Boolean | False |
|JWT_BLACKLIST_STORE | Where to save blacklisted tokens. | [See here] (http://pythonhosted.org/simplekv/) | None |
|JWT_BLACKLIST_CHECKS | What token types to check against the blacklist. | 'refresh', 'all' | 'refresh' |

### Blacklist and Token Revoking
This supports optional blacklisting and token revoking out of the box. This will allow you
to revoke a specific token so a user can no longer access your endpoints. In order
to revoke a token, we need some storage where we can save a list of all the tokens
we have created, as well as if they have been revoked or not. In order to make
the underlying storage as agnostic as possible, we use [simplekv] (http://pythonhosted.org/simplekv/)
to provide assess to a variety of backends.

In production, it is important to use a backend that can have some sort of
persistent storage, so we don't 'forget' that we revoked a token if the flask
process is restarted. We also need something that can be safely used by the
multiple thread and processes running your application. At present we believe
redis is a good fit for this. It has the added benefit of removing expired tokens
from the store automatically, so it wont blow up into something huge.

We also have choose what tokens we want to check against the blacklist. We could
check all tokens (refresh and access), or only the refresh tokens. There are pros
and cons to either way (extra overhead on jwt_required endpoints vs someone being
able to use an access token freely until it expires). In this example, we are
going to only check refresh tokens, and set the access tokes to a small expires
time to help minimize damage that could be done with a stolen access token.
```python
from datetime import timedelta

import simplekv
import simplekv.memory
from flask import Flask, request, jsonify

from flask_jwt_extended import JWTManager, jwt_required, \
    get_jwt_identity, revoke_token, unrevoke_token, \
    get_stored_tokens, get_all_stored_tokens, create_access_token, \
    create_refresh_token, jwt_refresh_token_required

# Setup flask
app = Flask(__name__)
app.secret_key = 'super-secret'

# Configure access token expires time
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)

# Enable and configure the JWT blacklist / token revoke. We are using an in
# memory store for this example. In production, you should use something
# persistant (such as redis, memcached, sqlalchemy). See here for options:
# http://pythonhosted.org/simplekv/
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_STORE'] = simplekv.memory.DictStore()
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'refresh'

jwt = JWTManager(app)


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {
        'access_token': create_access_token(identity=username),
        'refresh_token': create_refresh_token(identity=username)
    }
    return jsonify(ret), 200


@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200


# Endpoint for listing tokens that have the same identity as you
@app.route('/auth/tokens', methods=['GET'])
@jwt_required
def list_identity_tokens():
    username = get_jwt_identity()
    return jsonify(get_stored_tokens(username)), 200


# Endpoint for listing all tokens. In your app, you should either not expose
# this endpoint, or put some addition security on top of it so only trusted users,
# (administrators, etc) can access it
@app.route('/auth/all-tokens')
def list_all_tokens():
    return jsonify(get_all_stored_tokens()), 200


# Endpoint for allowing users to revoke their tokens
@app.route('/auth/tokens/revoke/<string:jti>', methods=['PUT'])
@jwt_required
def change_jwt_revoke_state(jti):
    username = jwt_get_identity()
    try:
        token_data = get_stored_token(jti)
        if token_data['token']['identity'] != username:
            raise KeyError
        revoke_token(jti)
        return jsonify({"msg": "Token successfully revoked"}), 200
    except KeyError:
        return jsonify({'msg': 'Token not found'}), 404


# Endpoint for allowing users to unrevoke their tokens
@app.route('/auth/tokens/unrevoke/<string:jti>', methods=['PUT'])
@jwt_required
def change_jwt_unrevoke_state(jti):
    username = jwt_get_identity()
    try:
        token_data = get_stored_token(jti)
        if token_data['token']['identity'] != username:
            raise KeyError
        unrevoke_token(jti)
        return jsonify({"msg": "Token successfully unrevoked"}), 200
    except KeyError:
        return jsonify({'msg': 'Token not found'}), 404


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'})

if __name__ == '__main__':
    app.run()
```


# Testing and Code Coverage
We run all the unit tests with tox. This will test against python2.7, and 3.5 (although not tested, python3.3 and 3.4 should also be fully supported). This will also print out a code coverage report.
```
tox
```

# Documentation
Readthedocs coming soon(tm)!
