# Flask-JWT-Extended
[![Build Status](https://travis-ci.org/vimalloc/flask-jwt-extended.svg?branch=master)](https://travis-ci.org/vimalloc/flask-jwt-extended)
[![Coverage Status](https://coveralls.io/repos/github/vimalloc/flask-jwt-extended/badge.svg)](https://coveralls.io/github/vimalloc/flask-jwt-extended)

Flask-JWT-Extended adds support for using JSON Web Tokens (JWT) to Flask for protecting views.

This has several optional features built it to make working with JSON Web Tokens
easier. These include:

* Support for adding custom claims to JSON Web Tokens
* [Refresh tokens] (https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
* Token freshness and separate view decorators to only allow fresh tokens
* Token revoking
* Storing tokens in cookies and CSRF protection

### Installation
The easiest way to start working with this extension with pip:
```
$ pip install flask-jwt-extended
```

If you prefer to install from source, you can clone this repo and run
```
$ python setup.py install
```

### Usage
[View the documentation online] (http://flask-jwt-extended.readthedocs.io/en/latest/)


### Testing and Code Coverage
We require 100% code coverage in our unit tests. We run all the unit tests with tox,
which will test against python2.7, 3.3, 3.4, and 3.5. Running tox will print out a
code coverage report
```
$ tox
```

### Generating Documentation
You can generate a local copy of the documentation. First, make sure you have
the flask sphinx theme cloned
```
$ git submodule update --init
```

Then, in the docs directory, run
```
$ make clean && make html
```
