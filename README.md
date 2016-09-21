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

curl --write-out "%{http_code}\n" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6dHJ1ZSwianRpIjoiZjhmNDlmMjUtNTQ4OS00NmRjLTkyOWUtZTU2Y2QxOGZhNzRlIiwidXNlcl9jbGFpbXMiOnt9LCJuYmYiOjE0NzQ0NzQ3OTEsImlhdCI6MTQ3NDQ3NDc5MSwiaWRlbnRpdHkiOiJ0ZXN0IiwiZXhwIjoxNDc0NDc1NjkxLCJ0eXBlIjoiYWNjZXNzIn0.vCy0Sec61i9prcGIRRCbG8e9NV6_wFH2ICFgUGCLKpc" http://localhost:5000/protected
{
  "hello": "world"
}
200
```

Refresh Tokens: TODO
Fresh Tokens: TODO
Custom Claims: TODO
Change Callbacks: TODO
Options: TODO
Blacklist/revoke: TODO

# Testing and Code Coverage
We run all the unit tests with tox. This will test against python2.7, and 3.5 (although not tested, python3.3 and 3.4 should also be fully supported). This will also print out a code coverage report.
```
tox
```

# Documentation
Readthedocs coming soon!
