# Flask-JWT-Extended
[![Build Status](https://travis-ci.org/vimalloc/flask-jwt-extended.svg?branch=master)](https://travis-ci.org/vimalloc/flask-jwt-extended)
[![Coverage Status](https://coveralls.io/repos/github/vimalloc/flask-jwt-extended/badge.svg)](https://coveralls.io/github/vimalloc/flask-jwt-extended)
[![PyPI version](https://badge.fury.io/py/Flask-JWT-Extended.svg)](https://badge.fury.io/py/Flask-JWT-Extended)
[![Documentation Status](https://readthedocs.org/projects/flask-jwt-extended/badge/)](http://flask-jwt-extended.readthedocs.io/en/latest/)

### Why Flask-JWT-Extended?

Flask-JWT-Extended adds support for using JSON Web Tokens (JWT) to Flask for protecting views.

This has several **optional** features built it to make working with JSON Web Tokens
easier. These include:

* Support for adding custom claims to JSON Web Tokens
* [Refresh tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
* Token freshness and separate view decorators to only allow fresh tokens
* Token revoking
* Storing tokens in cookies and CSRF protection

### Upgrading to the 3.x.x releases
[See here](https://github.com/vimalloc/flask-jwt-extended/releases/tag/3.0.0) for
help upgrading to the 3.x.x releases.

### Installation
[View Installation Instructions](http://flask-jwt-extended.readthedocs.io/en/latest/installation.html)


### Usage
[View the documentation online](http://flask-jwt-extended.readthedocs.io/en/latest/)


### Chatting
We are on irc! You can come chat with us in the ```#flask-jwt-extended``` channel on ```freenode```.


### Testing and Code Coverage
We require 100% code coverage in our unit tests. We run all the unit tests with tox,
which will test against python2.7, 3.3, 3.4, 3.5 and 3.6. Running tox will print out a
code coverage report
```
$ tox
```

### Generating Documentation
You can generate a local copy of the documentation. After installing the requirements,
go to the `docs` directory and run:
```
$ make clean && make html
```
