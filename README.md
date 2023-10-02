# Flask-JWT-Extended

### Features

Flask-JWT-Extended not only adds support for using JSON Web Tokens (JWT) to Flask for protecting routes,
but also many helpful (and **optional**) features built in to make working with JSON Web Tokens
easier. These include:

-   Adding custom claims to JSON Web Tokens
-   Automatic user loading (`current_user`).
-   Custom claims validation on received tokens
-   [Refresh tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
-   First class support for fresh tokens for making sensitive changes.
-   Token revoking/blocklisting
-   Storing tokens in cookies and CSRF protection

### Usage

[View the documentation online](https://flask-jwt-extended.readthedocs.io/en/stable/)

### Upgrading from 3.x.x to 4.0.0

[View the changes](https://flask-jwt-extended.readthedocs.io/en/stable/v4_upgrade_guide/)

### Changelog

You can view the changelog [here](https://github.com/vimalloc/flask-jwt-extended/releases).
This project follows [semantic versioning](https://semver.org/).

### Chatting

Come chat with the community or ask questions at https://discord.gg/EJBsbFd

### Contributing

Before making any changes, make sure to install the development requirements
and setup the git hooks which will automatically lint and format your changes.

```bash
pip install -r requirements.txt
pre-commit install
```

We require 100% code coverage in our unit tests. You can run the tests locally
with `tox` which ensures that all tests pass, tests provide complete code coverage,
documentation builds, and style guide are adhered to

```bash
tox
```

A subset of checks can also be ran by adding an argument to tox. The available
arguments are:

-   py37, py38, py39, py310, py311, py312, pypy3
    -   Run unit tests on the given python version
-   mypy
    -   Run mypy type checking
-   coverage
    -   Run a code coverage check
-   docs
    -   Ensure documentation builds and there are no broken links
-   style
    -   Ensure style guide is adhered to

```bash
tox -e py38
```

We also require features to be well documented. You can generate a local copy
of the documentation by going to the `docs` directory and running:

```bash
make clean && make html && open _build/html/index.html
```
