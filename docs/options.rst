Configuration Options
=====================

You can change many options for how this extension works via

.. code-block:: python

  app.config[OPTION_NAME] = new_options

The available options are:

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

================================= =========================================
``JWT_TOKEN_LOCATION``            Where to find the JWT in the request. The options are ``'headers'`` or
                                  ``'cookies'``. Defaults to ``'headers'``
``JWT_HEADER_NAME``               What header to look for the JWT in a request. Only used if we are sending
                                  the JWT in via headers. Defaults to ``'Authorization'``
``JWT_HEADER_TYPE``               What type of header the JWT is in. Defaults to ``'Bearer'``. This can be
                                  an empty string, in which case the header only contains the JWT
``JWT_COOKIE_CSRF_PROTECT``       Enable/disable CSRF protection. Only used when sending the JWT in via cookies
``JWT_ACCESS_CSRF_COOKIE_NAME``   Name of the CSRF access cookie. Defaults to ``'csrf_access_token'``. Only used
                                  if using cookies with CSRF protection enabled
``JWT_REFRESH_CSRF_COOKIE_NAME``  Name of the CSRF refresh cookie. Defaults to ``'csrf_refresh_token'``. Only used
                                  if using cookies with CSRF protection enabled
``JWT_CSRF_HEADER_NAME``          Name of the header that we will look for the CSRF double submit token in.
                                  Defaults to ``X-CSRF-TOKEN``. Only used if using cookies with CSRF protection enabled
``JWT_ACCESS_TOKEN_EXPIRES``      How long an access token should live before it expires. This takes a
                                  ``datetime.timedelta``, and defaults to 15 minutes
``JWT_REFRESH_TOKEN_EXPIRES``     How long a refresh token should live before it expires. This takes a
                                  ``datetime.timedelta``, and defaults to 30 days
``JWT_ALGORITHM``                 Which algorithm to sign the JWT with. `See here
                                  <https://pyjwt.readthedocs.io/en/latest/algorithms.html>`_ for the options. Defaults
                                  to ``'HS256'``. Note that Asymmetric (Public-key) Algorithms are not currently supported.
``JWT_BLACKLIST_ENABLED``         Enable/disable token blackliting and revoking. Defaults to ``False``
``JWT_BLACKLIST_STORE``           Where to save created and revoked tokens. `See here 
                                  <http://pythonhosted.org/simplekv/>`_ for options.
``JWT_BLACKLIST_CHECKS``          What token types to check against the blacklist. Options are
                                  ``'refresh'`` or  ``'all'``. Defaults to ``'refresh'``
================================= =========================================
