Configuration Options
=====================
You can change many options for this extension works via `Flask's Configuration
Handling <https://flask.palletsprojects.com/en/1.1.x/config/#configuration-handling>`_.
For example:

.. code-block:: python

  app.config["OPTION_NAME"] = option_value

Overview:
~~~~~~~~~

- `General Options:`_

  * `JWT_ACCESS_TOKEN_EXPIRES`_
  * `JWT_ALGORITHM`_
  * `JWT_DECODE_ALGORITHMS`_
  * `JWT_DECODE_AUDIENCE`_
  * `JWT_DECODE_ISSUER`_
  * `JWT_DECODE_LEEWAY`_
  * `JWT_ENCODE_AUDIENCE`_
  * `JWT_ENCODE_ISSUER`_
  * `JWT_ENCODE_NBF`_
  * `JWT_ERROR_MESSAGE_KEY`_
  * `JWT_IDENTITY_CLAIM`_
  * `JWT_PRIVATE_KEY`_
  * `JWT_PUBLIC_KEY`_
  * `JWT_REFRESH_TOKEN_EXPIRES`_
  * `JWT_SECRET_KEY`_
  * `JWT_TOKEN_LOCATION`_
  * `JWT_VERIFY_SUB`_

- `Header Options:`_

  * `JWT_HEADER_NAME`_
  * `JWT_HEADER_TYPE`_

- `Cookie Options:`_

  * `JWT_ACCESS_COOKIE_NAME`_
  * `JWT_ACCESS_COOKIE_PATH`_
  * `JWT_COOKIE_CSRF_PROTECT`_
  * `JWT_COOKIE_DOMAIN`_
  * `JWT_COOKIE_SAMESITE`_
  * `JWT_COOKIE_SECURE`_
  * `JWT_REFRESH_COOKIE_NAME`_
  * `JWT_REFRESH_COOKIE_PATH`_
  * `JWT_SESSION_COOKIE`_

- `Cross Site Request Forgery Options:`_

  * `JWT_ACCESS_CSRF_COOKIE_NAME`_
  * `JWT_ACCESS_CSRF_COOKIE_PATH`_
  * `JWT_ACCESS_CSRF_FIELD_NAME`_
  * `JWT_ACCESS_CSRF_HEADER_NAME`_
  * `JWT_CSRF_CHECK_FORM`_
  * `JWT_CSRF_IN_COOKIES`_
  * `JWT_CSRF_METHODS`_
  * `JWT_REFRESH_CSRF_COOKIE_NAME`_
  * `JWT_REFRESH_CSRF_COOKIE_PATH`_
  * `JWT_REFRESH_CSRF_FIELD_NAME`_
  * `JWT_REFRESH_CSRF_HEADER_NAME`_

- `Query String Options:`_

  * `JWT_QUERY_STRING_NAME`_
  * `JWT_QUERY_STRING_VALUE_PREFIX`_

- `JSON Body Options:`_

  * `JWT_JSON_KEY`_
  * `JWT_REFRESH_JSON_KEY`_

General Options:
~~~~~~~~~~~~~~~~

.. _JWT_ACCESS_TOKEN_EXPIRES:
.. py:data:: JWT_ACCESS_TOKEN_EXPIRES

    How long an access token should be valid before it expires. This can be a
    `datetime.timedelta <https://docs.python.org/3/library/datetime.html#timedelta-objects>`_,
    `dateutil.relativedelta <https://dateutil.readthedocs.io/en/stable/relativedelta.html>`_,
    or a number of seconds (``Integer``).

    If set to ``False`` tokens will never expire. **This is dangerous and should
    be avoided in most case**

    This can be overridden on a per token basis by passing the ``expires_delta``
    argument to :func:`flask_jwt_extended.create_access_token`

    Default: ``datetime.timedelta(minutes=15)``


.. _JWT_ALGORITHM:
.. py:data:: JWT_ALGORITHM

    Which algorithm to sign the JWT with. See `PyJWT <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_
    for the available algorithms.

    Default: ``"HS256"``


.. _JWT_DECODE_ALGORITHMS:
.. py:data:: JWT_DECODE_ALGORITHMS

    Which algorithms to use when decoding a JWT. See `PyJWT <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_
    for the available algorithms.

    By default this will always be the same algorithm that is defined in ``JWT_ALGORITHM``.

    Default: ``["HS256"]``


.. _JWT_DECODE_AUDIENCE:
.. py:data:: JWT_DECODE_AUDIENCE

    The string or list of audiences (``aud``) expected in a JWT when decoding it.

    Default: ``None``


.. _JWT_DECODE_ISSUER:
.. py:data:: JWT_DECODE_ISSUER

    The issuer (``iss``) you expect in a JWT when decoding it.

    Default: ``None``


.. _JWT_DECODE_LEEWAY:
.. py:data:: JWT_DECODE_LEEWAY

    The number of seconds a token will be considered valid before the Not Before
    Time (`nbf) and after the Expires Time (`exp`). This can be useful when
    dealing with clock drift between clients.

    Default: ``0``


.. _JWT_ENCODE_AUDIENCE:
.. py:data:: JWT_ENCODE_AUDIENCE

    The string or list of audiences (``aud``) for created JWTs.

    Default: ``None``


.. _JWT_ENCODE_ISSUER:
.. py:data:: JWT_ENCODE_ISSUER

    The issuer (``iss``) for created JWTs.

    Default: ``None``


.. _JWT_ENCODE_NBF:
.. py:data:: JWT_ENCODE_NBF

    The not before (``nbf``) claim which defines that a JWT MUST NOT be accepted for processing during decode.

    Default: ``True``


.. _JWT_ERROR_MESSAGE_KEY:
.. py:data:: JWT_ERROR_MESSAGE_KEY

    The key for error messages in a JSON response returned by this extension.

    Default: ``"msg"``


.. _JWT_IDENTITY_CLAIM:
.. py:data:: JWT_IDENTITY_CLAIM

    The claim in a JWT that is used as the source of identity.

    Default: ``"sub"``


.. _JWT_PRIVATE_KEY:
.. py:data:: JWT_PRIVATE_KEY

    The secret key used to encode JWTs when using an asymmetric signing
    algorithm (such as ``RS*`` or ``ES*``). The key must be in PEM format.

    **Do not reveal the secret key when posting questions or committing code.**

    Default: ``None``


.. _JWT_PUBLIC_KEY:
.. py:data:: JWT_PUBLIC_KEY

    The secret key used to decode JWTs when using an asymmetric signing
    algorithm (such as ``RS*`` or ``ES*``). The key must be in PEM format.

    Default: ``None``


.. _JWT_REFRESH_TOKEN_EXPIRES:
.. py:data:: JWT_REFRESH_TOKEN_EXPIRES

    How long a refresh token should be valid before it expires. This can be a
    `datetime.timedelta <https://docs.python.org/3/library/datetime.html#timedelta-objects>`_,
    `dateutil.relativedelta <https://dateutil.readthedocs.io/en/stable/relativedelta.html>`_,
    or a number of seconds (``Integer``).

    If set to ``False`` tokens will never expire. **This is dangerous and should
    be avoided in most case**

    This can be overridden on a per token basis by passing the ``expires_delta``
    argument to :func:`flask_jwt_extended.create_refresh_token`

    Default: ``datetime.timedelta(days=30)``


.. _JWT_SECRET_KEY:
.. py:data:: JWT_SECRET_KEY

    The secret key used to encode and decode JWTs when using a symmetric signing
    algorithm (such as ``HS*``). It should be a long random string of bytes,
    although unicode is accepted too. For example, copy the output of this to
    your config.

    .. code-block ::

     $ python -c 'import os; print(os.urandom(16))'
     b'_5#y2L"F4Q8z\n\xec]/'

    If this value is not set, Flask's `SECRET_KEY <https://flask.palletsprojects.com/en/1.1.x/config/#SECRET_KEY>`_
    is used instead.

    **Do not reveal the secret key when posting questions or committing code.**

    Note: there is ever a need to invalidate all issued tokens (e.g. a security flaw was found,
    or the revoked token database was lost), this can be easily done by changing the JWT_SECRET_KEY
    (or Flask's SECRET_KEY, if JWT_SECRET_KEY is unset).


    Default: ``None``


.. _JWT_TOKEN_LOCATION:
.. py:data:: JWT_TOKEN_LOCATION

    Where to look for a JWT when processing a request. The available options
    are ``"headers"``, ``"cookies"``, ``"query_string"``, and ``"json"``.

    You can pass in a list to check more then one location, for example
    ``["headers", "cookies"]``. The order of the list sets the precedence of
    where JWTs will be looked for.

    This can be overridden on a per-route basis by using the ``locations``
    argument in :func:`flask_jwt_extended.jwt_required`.

    Default: ``"headers"``

.. _JWT_VERIFY_SUB:
.. py:data:: JWT_VERIFY_SUB

    Control whether the ``sub`` claim is verified during JWT decoding.

    The ``sub`` claim MUST be a ``str`` according the the JWT spec. Setting this option
    to ``True`` (the default) will enforce this requirement, and consider non-compliant
    JWTs invalid. Setting the option to ``False`` will skip this validation of the type
    of the ``sub`` claim, allowing any type for the ``sub`` claim to be considered valid.

    Default: ``True``


Header Options:
~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via headers.

.. _JWT_HEADER_NAME:
.. py:data:: JWT_HEADER_NAME

    What header should contain the JWT in a request

    Default: ``"Authorization"``


.. _JWT_HEADER_TYPE:
.. py:data:: JWT_HEADER_TYPE

    What type of header the JWT is in. If this is an empty string, the header
    should contain nothing besides the JWT.

    Default: ``"Bearer"``


Cookie Options:
~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via cookies.

.. _JWT_ACCESS_COOKIE_NAME:
.. py:data:: JWT_ACCESS_COOKIE_NAME

    The name of the cookie that will hold the access token.

    Default: ``"access_token_cookie"``


.. _JWT_ACCESS_COOKIE_PATH:
.. py:data:: JWT_ACCESS_COOKIE_PATH

    The path for the access cookies

    Default: ``"/"``


.. _JWT_COOKIE_CSRF_PROTECT:
.. py:data:: JWT_COOKIE_CSRF_PROTECT

    Controls if Cross Site Request Forgery (CSRF) protection is enabled when using
    cookies.

    **This should always be True in production**

    Default: ``True``


.. _JWT_COOKIE_DOMAIN:
.. py:data:: JWT_COOKIE_DOMAIN

    Value to use for cross domain cookies. For example, if ``JWT_COOKIE_DOMAIN`` is
    ``".example.com"``, the cookies will be set so they are readable by the domains
    www.example.com, foo.example.com etc. Otherwise, a cookie will only be
    readable by the domain that set it.

    Default: ``None``


.. _JWT_COOKIE_SAMESITE:
.. py:data:: JWT_COOKIE_SAMESITE

    Controls how the cookies should be sent in a cross-site browsing context.
    Available options are ``"None"``, ``"Lax"``, or ``"Strict"``.

    To use ``SameSite=None``, you must set this option to the string ``"None"``
    as well as setting ``JWT_COOKIE_SECURE`` to ``True``.

    See the `MDN docs <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite>`_
    for more information.

    Default: ``None``, which is treated as ``"Lax"`` by browsers.


.. _JWT_COOKIE_SECURE:
.. py:data:: JWT_COOKIE_SECURE

    Controls if the ``secure`` flag should be placed on cookies created by this
    extension. If a cookie is marked as ``secure`` it will only be sent by the
    web browser over an HTTPS connection.

    **This should always be True in production.**

    Default: ``False``


.. _JWT_REFRESH_COOKIE_NAME:
.. py:data:: JWT_REFRESH_COOKIE_NAME

    The name of the cookie that will hold the refresh token.

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``"refresh_token_cookie"``


.. _JWT_REFRESH_COOKIE_PATH:
.. py:data:: JWT_REFRESH_COOKIE_PATH

    The path for the refresh cookies

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``"/"``


.. _JWT_SESSION_COOKIE:
.. py:data:: JWT_SESSION_COOKIE

    Controls if the cookies will be set as session cookies, which are deleted when
    the browser is closed.

    Default: ``True``


Cross Site Request Forgery Options:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via cookies and
``JWT_COOKIE_CSRF_PROTECT`` is ``True``.

.. _JWT_ACCESS_CSRF_COOKIE_NAME:
.. py:data:: JWT_ACCESS_CSRF_COOKIE_NAME

    The name of the cookie that contains the CSRF double submit token. Only
    applicable if ``JWT_CSRF_IN_COOKIES`` is ``True``

    Default: ``csrf_access_token``


.. _JWT_ACCESS_CSRF_COOKIE_PATH:
.. py:data:: JWT_ACCESS_CSRF_COOKIE_PATH

    The path of the access CSRF double submit cookie.

    Default: ``"/"``


.. _JWT_ACCESS_CSRF_FIELD_NAME:
.. py:data:: JWT_ACCESS_CSRF_FIELD_NAME

    Name of the form field that should contain the CSRF double submit token for
    an access token. Only applicable if ``JWT_CSRF_CHECK_FORM`` is ``True``

    Default: ``"csrf_token"``


.. _JWT_ACCESS_CSRF_HEADER_NAME:
.. py:data:: JWT_ACCESS_CSRF_HEADER_NAME

    The name of the header on an incoming request that should contain the CSRF
    double submit token.

    Default: ``"X-CSRF-TOKEN"``


.. _JWT_CSRF_CHECK_FORM:
.. py:data:: JWT_CSRF_CHECK_FORM

    Controls if form data should also be check for the CSRF double submit token.

    Default: ``False``


.. _JWT_CSRF_IN_COOKIES:
.. py:data:: JWT_CSRF_IN_COOKIES

    Controls if the CSRF double submit token will be stored in additional cookies.
    If setting this to ``False``, you can use :func:`flask_jwt_extended.get_csrf_token`
    to get the csrf token from an encoded JWT, and return it to your frontend in
    whatever way suites your application.

    Default: ``True``


.. _JWT_CSRF_METHODS:
.. py:data:: JWT_CSRF_METHODS

    A list of HTTP methods that we should do CSRF checks on.

    Default: ``["POST", "PUT", "PATCH", "DELETE"]``


.. _JWT_REFRESH_CSRF_COOKIE_NAME:
.. py:data:: JWT_REFRESH_CSRF_COOKIE_NAME

    The name of the cookie that contains the CSRF double submit token. Only
    applicable if ``JWT_CSRF_IN_COOKIES`` is ``True``

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``csrf_refresh_token``


.. _JWT_REFRESH_CSRF_COOKIE_PATH:
.. py:data:: JWT_REFRESH_CSRF_COOKIE_PATH

    The path of the refresh CSRF double submit cookie.

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``"/"``


.. _JWT_REFRESH_CSRF_FIELD_NAME:
.. py:data:: JWT_REFRESH_CSRF_FIELD_NAME

    Name of the form field that should contain the CSRF double submit token for
    a refresh token. Only applicable if ``JWT_CSRF_CHECK_FORM`` is ``True``

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``"csrf_token"``


.. _JWT_REFRESH_CSRF_HEADER_NAME:
.. py:data:: JWT_REFRESH_CSRF_HEADER_NAME

    The name of the header on an incoming request that should contain the CSRF
    double submit token.

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``"X-CSRF-TOKEN"``


Query String Options:
~~~~~~~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via query string.

.. _JWT_QUERY_STRING_NAME:
.. py:data:: JWT_QUERY_STRING_NAME

    What query string parameter should contain the JWT.

    Default: ``"jwt"``


.. _JWT_QUERY_STRING_VALUE_PREFIX:
.. py:data:: JWT_QUERY_STRING_VALUE_PREFIX

    An optional prefix string that should show up before the JWT in a
    query string parameter.

    For example, if this was ``"Bearer "``, the query string should look like
    ``"/endpoint?jwt=Bearer <JWT>"``

    Default: ``""``


JSON Body Options:
~~~~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via the JSON body.

.. _JWT_JSON_KEY:
.. py:data:: JWT_JSON_KEY

    What key should contain the access token in the JSON body of a request.

    Default: ``"access_token"``


.. _JWT_REFRESH_JSON_KEY:
.. py:data:: JWT_REFRESH_JSON_KEY

    What key should contain the refresh token in the JSON body of a request.

    Default: ``"access_token"``
