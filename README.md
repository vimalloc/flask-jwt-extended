# Flask-JWT-Extended
Flask-JWT-Extended adds support for using JSON Web Tokens (JWT) to Flask for protecting views.

This has built in support for entirely stateless 'vanilla' JSON Web Tokens. It also has optional [refresh tokens] (https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/), token freshness (reuqires users to re-authenticate if they haven't in a while when accessing critical views), and optional token revokation (stateful).

Token revokation makes no assumption about your underlying storage for revoked tokens. It uses [simplekv] (https://github.com/mbr/simplekv) to utilize the underlying storage of your choice.

# Installation
The easiest way to start working with this extension is (THIS WILL BE IN PIP IN A FEW HOURS):
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
jwt = JWTManager(app)


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
However, this is only the tip of the iceberg for what we can do


### Adding Custom Claims to the Access Token
You may want to store additional information in the access token. Perhaps you want
to save the access roles this user has so you can access them in the view functions
(without having to make a database call each time). This can be done with the 
user_claims_loader, and access with the 'get_jwt_claims()' method in a protected endpoint
```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    get_jwt_claims

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    # These must be json serializable
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
By setting the access tokens to a shorter lifetime (see Options bellow), and utilizing
fresh tokenks for critical endpoint (see Fresh Tokens bellow) we can help reduce the
damage done if an access token is stolen. Here is an example on how to use them:

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


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200

if __name__ == '__main__':
    app.run()
```
As you can see, there are a few things different in this example. First and formost
is the create_refresh_token method, which as the name implies, will generate a new
refresh token. Second is the @jwt_refresh_token_required decorator. This will
protect a view so that it can only be accessed if a valid refresh token is supplied
in the request (an access token cannot access this view). Finally, we have the
method get_jwt_identity. This will return the identity of the token used to access
this endpoint (and works for both access and refresh tokens).

We can now this refresh token to generate new access tokens without the user having
to login with their username and passwords all the time. Neat. Now lets look at
token freshness to see how we can improve upon this further.

### Token Freshness
We have the idea of token freshness built into this system. In a nutshell, you can
choose to mark some access tokens as fresh and others as non-fresh, and a 
fresh_jwt_required decorator to only allow fresh tokens to access some views.

This is useful for allowing fresh logins to do some critical things (maybe change
a password, or complete an online purchase), but to deny those features to
non-fresh tokens without verifying their username/password. This still allows your
users to access any of the normal jwt_protected endpoints while using a non-fresh
token. Using these wisely can lead to a more secure site, without creating
unnecessarily bad users experiences by having to re-login all the time.

The provided API gives you the power to use the token freshness however you may
want to. A very natural way to do this would be to mark a token as fresh when they
first login, mark any tokens generated with the refresh token to be not fresh,
and provide one more endpoint for generating new fresh tokens (via re-authing)
without generating a new refresh token to go with it.
```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, \
    jwt_refresh_token_required, create_refresh_token, get_jwt_identity, \
    fresh_jwt_required

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {
        'access_token': create_access_token(identity=username, fresh=True),
        'refresh_token': create_refresh_token(identity=username)
    }
    return jsonify(ret), 200


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if username != 'test' and password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    ret = {'access_token': create_access_token(identity=username, fresh=True)}
    return jsonify(ret), 200


@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user, fresh=False)
    }
    return jsonify(ret), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200


@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'hello': 'from {}'.format(username)}), 200

if __name__ == '__main__':
    app.run()
```
The only real things to note here is the new @fresh_jwt_required decorator, and
the optional 'fresh=' keyword passed to the 'create_access_token' methods.

### Changing Default Behaviors
We provide what we think are sensible behaivors when attempting to access a protected
endpoint. If the endpoint could not be used for any reason (missing/expired/invalid/etc
access token) we will return json in the format of {'msg': <why accesing endpoint failed>}
along with an appropiate http status code (generally 401 or 422). However, you may want
to cusomize what is sent back in these cases. We can do that with the jwt_manager
'loader' functions. 
```python
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)
app.secret_key = 'super-secret'  # Change this!
jwt = JWTManager(app)


@jwt.expired_token_callback
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
Now if an expired token tries to access the protected endpoint, we will get the
json we specified back instead of our default behaivor.

The available loader functions are:
* expired_token_loader
* invalid_token_loader  (function takes one arg, which is an error string of why its invalid)
* unauthorized_loader
* needs_fresh_token_loader
* revoked_token_loader  (see Blacklist and Token Revoking bellow)

### Options
You can change many options for how this extension works via 
```python
app.config[OPTION_NAME] = new_options
```
The available options are:
* JWT_ACCESS_TOKEN_EXPIRES: datetime.timedelta of how long an access token should
live before it expires (Defaults to 15 minutes)
* JWT_REFRESH_TOKEN_EXPIRES: datetime.timedelta of how long a refresh token should
live before it expires (Defaults to 30 days)
* JWT_ALGORITHM: Which algorithm to use with the JWT. See [here] (https://pyjwt.readthedocs.io/en/latest/algorithms.html)
for options (Defaults to HS256)
* JWT_BLACKLIST_ENABLED: If token blacklist/revoking should be enabled (Default False)
* JWT_BLACKLIST_STORE: Where to save blacklisted tokens. See [here] (http://pythonhosted.org/simplekv/)
for options (Default None)
* JWT_BLACKLIST_CHECKS: What tokens to check against the blacklist. Options are 'refresh' which
will only check refresh tokens, and 'all' which will check refresh and access tokens. Defaults
to 'refresh'

### Blacklist and Token Revoking
TODO


# Testing and Code Coverage
We run all the unit tests with tox. This will test against python2.7, and 3.5 (although not tested, python3.3 and 3.4 should also be fully supported). This will also print out a code coverage report.
```
tox
```

# Documentation
Readthedocs coming soon!
