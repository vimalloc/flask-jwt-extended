Configuration Options
=====================

You can change many options for how this extension works via

.. code-block:: python

  app.config[OPTION_NAME] = new_options

General Options:
~~~~~~~~~~~~~~~~

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_TOKEN_LOCATION``            Where to look for a JWT when processing a request. The
                                  options are ``'headers'`` or ``'cookies'``. You can pass
                                  in a list to check more then one location, such as: ``['headers', 'cookies']``.
                                  Defaults to ``'headers'``
``JWT_ACCESS_TOKEN_EXPIRES``      How long an access token should live before it expires. This
                                  takes a ``datetime.timedelta``, and defaults to 15 minutes
``JWT_REFRESH_TOKEN_EXPIRES``     How long a refresh token should live before it expires. This
                                  takes a ``datetime.timedelta``, and defaults to 30 days
``JWT_ALGORITHM``                 Which algorithm to sign the JWT with. `See here <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_
                                  for the options. Defaults to ``'HS256'``.
``JWT_SECRET_KEY``                The secret key needed for symmetric based signing algorithms,
                                  such as ``HS*``. If this is not set, we use the
                                  flask ``SECRET_KEY`` value instead.
``JWT_PUBLIC_KEY``                The public key needed for asymmetric based signing algorithms,
                                  such as ``RS*`` or ``ES*``. PEM format expected.
``JWT_PRIVATE_KEY``               The private key needed for asymmetric based signing algorithms,
                                  such as ``RS*`` or ``ES*``. PEM format expected.
``JWT_IDENTITY_CLAIM``            Claim in the tokens that is used as source of identity.
                                  For interoperativity, the JWT RFC recommends using ``'sub'``.
                                  Defaults to ``'identity'``.
================================= =========================================


Header Options:
~~~~~~~~~~~~~~~
These are only applicable if ``JWT_TOKEN_LOCATION`` is set to use headers.

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_HEADER_NAME``               What header to look for the JWT in a request. Defaults to ``'Authorization'``
``JWT_HEADER_TYPE``               What type of header the JWT is in. Defaults to ``'Bearer'``. This can be
                                  an empty string, in which case the header contains only the JWT
                                  (insead of something like ``HeaderName: Bearer <JWT>``)
================================= =========================================


Cookie Options:
~~~~~~~~~~~~~~~
These are only applicable if ``JWT_TOKEN_LOCATION`` is set to use cookies.

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_ACCESS_COOKIE_NAME``        The name of the cookie that holds the access token. Defaults to ``access_token_cookie``
``JWT_REFRESH_COOKIE_NAME``       The name of the cookie that holds the refresh token. Defaults to ``refresh_token_cookie``
``JWT_ACCESS_COOKIE_PATH``        What ``path`` should be set for the access cookie. Defaults to ``'/'``,
                                  which will cause this access cookie to be sent in with every request.
                                  Should be modified for only the paths that need the access cookie
``JWT_REFRESH_COOKIE_PATH``       What ``path`` should be set for the refresh cookie.
                                  Defaults to ``'/'``, which will cause this refresh cookie
                                  to be sent in with every request. Should be modified
                                  for only the paths that need the refresh cookie
``JWT_COOKIE_SECURE``             If the secure flag should be set on your JWT cookies. This will only allow
                                  the cookies to be sent over https. Defaults to ``False``, but in production
                                  this should likely be set to ``True``.
``JWT_COOKIE_DOMAIN``             Value to use for cross domain cookies. Defaults to ``None`` which sets
                                  this cookie to only be readable by the domain that set it.
``JWT_SESSION_COOKIE``            If the cookies should be session cookies (deleted when the
                                  browser is closed) or persistent cookies (never expire).
                                  Defaults to ``True`` (session cookies).
``JWT_COOKIE_CSRF_PROTECT``       Enable/disable CSRF protection when using cookies. Defaults to ``True``.
================================= =========================================

Cross Site Request Forgery Options:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
These are only applicable if ``JWT_TOKEN_LOCATION`` is set to use cookies and
``JWT_COOKIE_CSRF_PROTECT`` is True.

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
================================= =========================================


Blacklist Options:
~~~~~~~~~~~~~~~~~~

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_BLACKLIST_ENABLED``         Enable/disable token blacklisting and revoking. Defaults to ``False``
``JWT_BLACKLIST_TOKEN_CHECKS``    What token types to check against the blacklist. The options are
                                  ``'refresh'`` or  ``'access'``. You can pass in a list to check
                                  more then one type. Defaults to ``['access', 'refresh']``.
                                  Only used if blacklisting is enabled.
================================= =========================================
