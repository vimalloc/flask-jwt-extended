# Flask-JWT-Extended
Flask-JWT-Extended adds support for using JSON Web Tokens (JWT) to Flask for protecting views.

This has built in support for entirely stateless 'vanilla' JSON Web Tokens. It also has optional [refresh tokens] (https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/), token freshness (reuqires users to re-authenticate if they haven't in a while when accessing critical views), and optional token revokation (stateful).

Token revokation makes no assumption about your underlying storage for revoked tokens. It utilizes [simplekv] (https://github.com/mbr/simplekv) to utilize the underlying storage of your choice.

# Installation
The easiest way to start working with this extension is (coming tomorrow):
```
pip install flask-jwt-extended
```

If you prefer to install from source, you can clone this repo and run
```
python setup.py install
```

# Usage
Examples coming tomorrow :)

# Testing and Code Coverage
We run all the unit tests with tox. This will test against python2.7, and 3.5 (although not tested, python3.3 and 3.4 should also be fully supported). This will also print out a code coverage report.
```
tox
```

# Code coverage
TODO

# Documentation
Readthedocs coming soon!
