# Flask-JWT-Extended
[![Build Status](https://travis-ci.org/vimalloc/flask-jwt-extended.svg?branch=master)](https://travis-ci.org/vimalloc/flask-jwt-extended)
[![Coverage Status](https://coveralls.io/repos/github/vimalloc/flask-jwt-extended/badge.svg?branch=master)](https://coveralls.io/github/vimalloc/flask-jwt-extended?branch=master)
[![PyPI version](https://badge.fury.io/py/Flask-JWT-Extended.svg)](https://badge.fury.io/py/Flask-JWT-Extended)
[![Documentation Status](https://readthedocs.org/projects/flask-jwt-extended/badge/)](http://flask-jwt-extended.readthedocs.io/en/latest/)

### Features
Flask-JWT-Extended not only adds support for using JSON Web Tokens (JWT) to Flask for protecting views,
but also many helpful (and **optional**) features  built in to make working with JSON Web Tokens
easier. These include:

* Support for adding custom claims to JSON Web Tokens
* Custom claims validation on received tokens
* Creating tokens from complex objects or complex object from received tokens
* [Refresh tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
* Token freshness and separate view decorators to only allow fresh tokens
* Token revoking/blacklisting
* Storing tokens in cookies and CSRF protection

### Usage
[View the documentation online](https://flask-jwt-extended.readthedocs.io/en/stable/)

### Changelog
You can view the changelog [here](https://github.com/vimalloc/flask-jwt-extended/releases).
This project follows [semantic versioning](https://semver.org/).

### Chatting
Come chat with the community or ask questions at https://discord.gg/EJBsbFd

### Contributing
We require 100% code coverage in our unit tests. You can run the tests locally
with `tox` which will print out a code coverage report and verify the code
format looks good.
```
$ tox
```

We use [black](https://github.com/psf/black) to format all our code. Any code
not formatted will be treated as an error on on a `tox` run. To automatically
format code, run:
```
$ black --target-version py35 setup.py flask_jwt_extended/ tests/
```

We also require features to be well documented.  You can generate a local copy
of the documentation by going to the `docs` directory and running:
```
$ make clean && make html
```
