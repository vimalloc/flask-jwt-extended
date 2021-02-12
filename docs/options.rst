Configuration Options
=====================
You can change many options for this extension works via `Flask's Configuration
Handling <https://flask.palletsprojects.com/en/1.1.x/config/#configuration-handling>`_.
For example:

.. code-block:: python

  app.config["OPTION_NAME"] = option_value

General Options:
~~~~~~~~~~~~~~~~

.. py:data:: JWT_TOKEN_LOCATION

    Where to look for a JWT when processing a request. The available options
    are ``"headers"``, ``"cookies"``, ``"query_string"``, and ``"json"``.

    You can pass in a list to check more then one location, for example
    ``["headers", "cookies"]``. The order of the list sets the precedence of
    where JWTs will be looked for.

    This can be overriden on a per-route basis by using the ``locations``
    argument in :func:`flask_jwt_extended.jwt_required`.

    Default: ``"headers"``


.. py:data:: JWT_ACCESS_TOKEN_EXPIRES

    How long an access token should be valid before it expires. This can be a
    `datetime.timedelta <https://docs.python.org/3/library/datetime.html#timedelta-objects>`_,
    `dateutil.relativedelta <https://dateutil.readthedocs.io/en/stable/relativedelta.html>`_,
    or a number of seconds (``Integer``).

    If set to ``False`` tokens will never expire. **This is dangerous and should
    be avoided in most case**

    Default: ``datetime.timedelta(minutes=15)``


.. py:data:: JWT_REFRESH_TOKEN_EXPIRES

    How long an access token should be valid before it expires. This can be a
    `datetime.timedelta <https://docs.python.org/3/library/datetime.html#timedelta-objects>`_,
    `dateutil.relativedelta <https://dateutil.readthedocs.io/en/stable/relativedelta.html>`_,
    or a number of seconds (``Integer``).

    If set to ``False`` tokens will never expire. **This is dangerous and should
    be avoided in most case**

    Default: ``datetime.timedelta(days=30)``


.. py:data:: JWT_ALGORITHM

    Which algorithm to sign the JWT with. See `PyJWT <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_
    for the available algorightms.

    Default: ``"HS256"``


.. py:data:: JWT_DECODE_ALGORITHMS

    Which algorithms to use when decoding a JWT. See `PyJWT <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_
    for the available algorightms.

    By default this will always be the same algorithm that is defined in ``JWT_ALGORITHM``.

    Default: ``["HS256"]``


.. py:data:: JWT_SECRET_KEY

    The secret key used to encode and decode JWTs when using a symmetric signing
    algorightm (such as ``HS*``). It should be a long random string of bytes,
    although unicode is accepted too. For example, copy the output of this to
    your config.

    .. code-block ::

     $ python -c 'import os; print(os.urandom(16))'
     b'_5#y2L"F4Q8z\n\xec]/'

    If this value is not set, Flask's `SECRET_KEY <https://flask.palletsprojects.com/en/1.1.x/config/#SECRET_KEY>`_
    is used instead.

    **Do not reveal the secret key when posting questions or committing code.**

    Default: ``None``


.. py:data:: JWT_PRIVATE_KEY

    The secret key used to encode JWTs when using an asymmetric signing
    algorightm (such as ``RS*`` or ``ES*``). The key must be in PEM format.

    **Do not reveal the secret key when posting questions or committing code.**

    Default: ``None``


.. py:data:: JWT_PUBLIC_KEY

    The secret key used to decode JWTs when using an asymmetric signing
    algorightm (such as ``RS*`` or ``ES*``). The key must be in PEM format.

    Default: ``None``


.. py:data:: JWT_DECODE_AUDIENCE

    The expected audience (``aud``) or list of audiences you expect in a JWT when
    decoding it.

    Default: ``None``


.. py:data:: JWT_DECODE_LEEWAY

    The number of seconds a token will be considered valid before the Not Before
    Time (`nbf) and after the Expires Time (`exp`). This can be useful when
    dealing with clock drift between clients.

    Default: ``0``


.. py:data:: JWT_IDENTITY_CLAIM

    The claim in a JWT that is used as the source of identity.

    Default: ``"sub"``


.. py:data:: JWT_ERROR_MESSAGE_KEY

    The key for error messages in a JSON response returned by this extension.

    Default: ``"msg"``


Header Options:
~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via headers.

.. py:data:: JWT_HEADER_NAME

    What header should contain the JWT in a request

    Default: ``"Authorization"``


.. py:data:: JWT_HEADER_TYPE

    What type of header the JWT is in. If this is an empty string, the header
    should contain nothing besides the JWT.

    Default: ``"Bearer"``


Cookie Options:
~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via cookies.

.. py:data:: JWT_COOKIE_SECURE

    Controls if the ``secure`` flag should be placed on cookies created by this
    extension. If a cookie is marked as ``secure`` it will only be sent by the
    web browser over an HTTPS connection.

    **This should always be True in production.**

    Default: ``False``


.. py:data:: JWT_COOKIE_SAMESITE

    Controls how the cookies should be sent in a cross-site browsing context.
    Available options are ``"None"``, ``"Lax"``, or ``"Strict"``.

    To use ``SameSite=None``, you must set this option to the string ``"None"``
    as well as setting ``JWT_COOKIE_SECURE`` to ``True``.

    See the `MDN docs <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite>`_
    for more information.

    Default: ``None``, which is treated as ``"Lax"`` by browsers.


.. py:data:: JWT_ACCESS_COOKIE_NAME

    The name of the cookie that will hold the access token.

    Default: ``"access_token_cookie"``


.. py:data:: JWT_REFRESH_COOKIE_NAME

    The name of the cookie that will hold the access token.

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``"refresh_token_cookie"``


.. py:data:: JWT_ACCESS_COOKIE_PATH

    The path for the access cookies

    Default: ``"/"``


.. py:data:: JWT_REFRESH_COOKIE_PATH

    The path for the refresh cookies

    Note: We generally do not recommend using refresh tokens with cookies. See
    :ref:`Implicit Refreshing With Cookies`.

    Default: ``"/"``


.. py:data:: JWT_COOKIE_DOMAIN

    Value to use for cross domain cookies. For example, if ``JWT_COOKIE_DOMAIN`` is
    ``".example.com"``, the cookies will be set so they are readable by the domains
    www.example.com, foo.example.com etc. Otherwise, a cookie will only be
    readable by the domain that set it.

    Default: ``None``


.. py:data:: JWT_SESSION_COOKIE

    Controls if the cookies will be set as session cookies, which are deleted when
    the browser is closed.

    Default: ``True``


.. py:data:: JWT_COOKIE_CSRF_PROTECT

    Controls if Cross Site Request Forgery (CSRF) protection is enabled when using
    cookies.

    **This should always be True in production**

    Default: ``True``


Cross Site Request Forgery Options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
These are only applicable if a route is configured to accept JWTs via cookies and
``JWT_COOKIE_CSRF_PROTECT`` is ``True``.

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_CSRF_METHODS``              The request types that will use CSRF protection. Defaults to
                                  ``['POST', 'PUT', 'PATCH', 'DELETE']``
``JWT_ACCESS_CSRF_HEADER_NAME``   Name of the header that should contain the CSRF double submit value
                                  for access tokens. Defaults to ``X-CSRF-TOKEN``.
``JWT_REFRESH_CSRF_HEADER_NAME``  Name of the header that should contains the CSRF double submit value
                                  for refresh tokens. Defaults to ``X-CSRF-TOKEN``.
``JWT_CSRF_IN_COOKIES``           If we should store the CSRF double submit value in
                                  another cookies when using ``set_access_cookies()`` and
                                  ``set_refresh_cookies()``. Defaults to ``True``. If this is
                                  False, you are responsible for getting the CSRF value to the
                                  callers (see: ``get_csrf_token(encoded_token)``).
``JWT_ACCESS_CSRF_COOKIE_NAME``   Name of the CSRF access cookie. Defaults to ``'csrf_access_token'``.
                                  Only applicable if ``JWT_CSRF_IN_COOKIES`` is ``True``
``JWT_REFRESH_CSRF_COOKIE_NAME``  Name of the CSRF refresh cookie. Defaults to ``'csrf_refresh_token'``.
                                  Only applicable if ``JWT_CSRF_IN_COOKIES`` is ``True``
``JWT_ACCESS_CSRF_COOKIE_PATH``   Path for the CSRF access cookie. Defaults to ``'/'``.
                                  Only applicable if ``JWT_CSRF_IN_COOKIES`` is ``True``
``JWT_REFRESH_CSRF_COOKIE_PATH``  Path of the CSRF refresh cookie. Defaults to ``'/'``.
                                  Only applicable if ``JWT_CSRF_IN_COOKIES`` is ``True``
``JWT_CSRF_CHECK_FORM``           When no CSRF token can be found in the header, check the form data. Defaults to
                                  ``False``.
``JWT_ACCESS_CSRF_FIELD_NAME``    Name of the form field that should contain the CSRF double submit value for access
                                  tokens when no header is present. Only applicable if ``JWT_CSRF_CHECK_FORM`` is
                                  ``True``. Defaults to ``'csrf_token'``.
``JWT_REFRESH_CSRF_FIELD_NAME``   Name of the form field that should contain the CSRF double submit value for refresh
                                  tokens when no header is present. Only applicable if ``JWT_CSRF_CHECK_FORM`` is
                                  ``True``. Defaults to ``'csrf_token'``.
================================= =========================================


Query String Options:
~~~~~~~~~~~~~~~~~~~~~
These are only applicable if ``JWT_TOKEN_LOCATION`` is set to use query strings.

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_QUERY_STRING_NAME``         What query paramater name to look for a JWT in a request. Defaults to ``'jwt'``
================================= =========================================



Json Body Options:
~~~~~~~~~~~~~~~~~~~~~
These are only applicable if ``JWT_TOKEN_LOCATION`` is set to use json data.

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_JSON_KEY``                  Key to look for in the body of an `application/json` request. Defaults to ``'access_token'``
``JWT_REFRESH_JSON_KEY``          Key to look for the refresh token in an `application/json` request. Defaults to ``'refresh_token'``
================================= =========================================
