# Flask-JWT-Extended
[![Build Status](https://travis-ci.org/vimalloc/flask-jwt-extended.svg?branch=master)](https://travis-ci.org/vimalloc/flask-jwt-extended)
[![Coverage Status](https://coveralls.io/repos/github/vimalloc/flask-jwt-extended/badge.svg)](https://coveralls.io/github/vimalloc/flask-jwt-extended)
[![PyPI version](https://badge.fury.io/py/Flask-JWT-Extended.svg)](https://badge.fury.io/py/Flask-JWT-Extended)
[![Documentation Status](https://readthedocs.org/projects/flask-jwt-extended/badge/)](http://flask-jwt-extended.readthedocs.io/en/latest/)

### When to use Flask-JWT-Extended?

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

### When *not* to use Flask-JWT-Extended?

This extension is very opinionated about what claims need to exist in received
JWTs to get all these extra features to work. If you are working with other JWT
providers, only using Flask for rapid prototyping of your application, or do
not care about any of these extra features, [Flask-JWT-Simple](https://github.com/vimalloc/flask-jwt-simple)
may be a better fit for your application. It is the sister extension of this
one (both maintained by me), which strips all of the extra features and opinionated
JWT requirements out.


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
We require 100% code coverage in our unit tests. You can run the tests locally
with `tox` which will print out a code coverage report. Creating a pull request
will run the tests against python 2.7, 3.3, 3,4, 3,5, 3,6, and PyPy.
```
$ tox
```

### Generating Documentation
You can generate a local copy of the documentation. After installing the requirements,
go to the `docs` directory and run:
```
$ make clean && make html
```
