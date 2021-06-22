4.0.0 Breaking Changes and Upgrade Guide
========================================
This release includes a lot of breaking changes that have been a long time coming,
and will require some manual intervention to upgrade your application. Breaking
changes are never fun, but I really believe they are for the best. As a result
of all these changes, this extension should be simpler to use, provide more
flexibility, and allow for easier additions to the API without introducing
further breaking changes. Here is everything you will need to be aware of when
upgrading to 4.0.0.

Encoded JWT Changes (IMPORTANT)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- The ``JWT_USER_CLAIMS`` configuration option has been removed. Now when creating
  JWTs with additional claims, those claims are put on the top level of the token,
  insetad of inside the the nested ``user_claims`` dictionary. This has the very
  important benefit of allowing you to override reserved claims (such as ``nbf``)
  which was not previously possible in this extension.

  **IMPORTANT NOTE**:

  This has the unfortunate side effect that any existing JWTs your application is
  using will not work correctly if they utilize additional claims. We **strongly**
  suggest changing your secret key to force all users to get the new format of
  JWTs. If that is not feasible for your appilication you could build a shim to
  handle both the old JWTs which store additional claims in the ``user_claims``
  key, and the new format where additional claims are now stored at the top
  level, until all the JWTs have had a chance to cycle to the new format.
- The default ``JWT_IDENTITY_CLAIM`` option is now ``sub`` instead of ``identity``.

General Changes
~~~~~~~~~~~~~~~
- Dropped support for everything before Python 3.6 (including Python 2).
- Requires PyJWT >= 2.0.0.
- Depreciation warnings in ``3.25.2`` have been removed and are now errors:

  - The ``JWT_CSRF_HEADER_NAME`` option has removed.
  - The ``jwt.expired_token_loader`` will error if the callback  does not take
    an argument for the expired token header and expired token payload.
  - The ``jwt.decode_key_loader`` will error if the callback  does not take an argument
    for the unverified_headers and the unverified_payload.

- Calling ``get_jwt()``, ``get_jwt_header()``, or ``get_jwt_identity()`` will raise
  a ``RuntimeError`` when called outside of a protected context (ie if you forgot
  ``@jwt.required()`` or ``verify_jwt_in_request()``).  Previously these calls
  would return ``None``.
- Calling ``get_jwt()`` or ``get_jwt_header()`` will return an empty dictionary
  if called from an optionally protected endpoint. Previously this would return ``None``.
- Calling ``get_current_user()`` or ``current_user`` will raise a ``RuntimeError``
  if no ``@jwt.user_lookup_loader`` callback is defined.

Blacklist Changes
~~~~~~~~~~~~~~~~~
- All occurrences of ``blacklist`` have been renamed to ``blocklist``
- The ``JWT_BLACKLIST_ENABLED`` option has been removed. If you do not want to
  check a JWT against your blocklist, do not register a callback function with
  ``@jwt.token_in_blocklist_loader``.
- The ``JWT_BLACKLIST_TOKEN_CHECKS`` option has been removed. If you don't want
  to check a given token type against the blocklist, specifically ignore it in
  your callback function by checking the ``jwt_payload["type"]`` and short
  circuiting accordingly. ``jwt_payload["type"]`` will be either ``"access"`` or ``"refresh"``.

Callback Function Changes
~~~~~~~~~~~~~~~~~~~~~~~~~
- Renamed ``@jwt.claims_verification_loader`` to ``@jwt.token_verification_loader``
- Renamed ``@jwt.claims_verification_failed_loader`` to ``@jwt.token_verification_failed_loader``
- Renamed ``@jwt.user_claims_loader`` to ``@jwt.additional_claims_loader``
- Renamed ``@jwt.user_in_blacklist_loader`` to ``@jwt.user_in_blocklist_loader``
- Renamed ``@jwt.user_loader_callback_loader`` to ``@jwt.user_lookup_loader``
- Renamed ``@jwt.user_loader_error_loader`` to ``@jwt.user_lookup_error_loader``
- The following callback functions have all been changed to take two arguments.
  Those arguments are the ``jwt_headers`` and ``jwt_payload``.

  - ``@jwt.needs_fresh_token_loader``
  - ``@jwt.revoked_token_loader``
  - ``@jwt.user_lookup_loader``
  - ``@jwt.user_lookup_error_loader``
  - ``@jwt.expired_token_loader``
  - ``@jwt.token_in_blocklist_loader``
  - ``@jwt.token_verification_loader``
  - ``@jwt.token_verification_failed_loader``

  .. code-block :: python

    @jwt.revoked_token_loader
    def revoked_token_response(jwt_header, jwt_payload):
        return jsonify(msg=f"I'm sorry {jwt_payload['sub']} I can't let you do that")

- The arguments for ``@jwt.decode_key_loader`` have been reversed to be consistent
  with the rest of the application. Previously the arguments were ``(jwt_payload, jwt_headers)``.
  Now they are ``(jwt_headers, jwt_payload)``.

API Changes
~~~~~~~~~~~
- All view decorators have been moved to a single decorator:
    - ``@jwt_required`` is now ``@jwt_required()``
    - ``@jwt_optional`` is now ``@jwt_required(optional=True)``
    - ``@fresh_jwt_required`` is now ``@jwt_required(fresh=True)``
    - ``@jwt_refresh_token_required`` is now ``@jwt_required(refresh=True)``
- All additional ``verify_jwt_in_request`` functions have been moved to a single method:
    - ``verify_jwt_in_request_optional()`` is now ``verify_jwt_in_request(optional=True)``
    - ``verify_jwt_refresh_token_in_request()`` is now ``verify_jwt_in_request(refresh=True)``
    - ``verify_fresh_jwt_in_request()`` is now ``verify_jwt_in_request(fresh=True)``
- Renamed ``get_raw_jwt()`` to ``get_jwt()``
- Renamed ``get_raw_jwt_headers()`` to ``get_jwt_headers()``
- Removed ``get_jwt_claims()``. Use ``get_jwt()`` instead.
- The ``headers`` argument in ``create_access_token()`` and ``create_refresh_token()``
  has been renamed to ``additional_headers``.

  - If you pass in the ``additional_headers``, it will now be merged with the
    headers returned by the ``@jwt.additional_headers_loader`` callback, with
    ties going to the ``additional_headers`` argument.

- The ``user_claims`` argument in ``create_access_token()`` and ``create_refresh_token()``
  has been renamed to ``additional_claims``.

  - If you pass in the ``additional_claims`` option, it will now be merged with
    the claims returned by the ``@jwt.additional_claims_loader`` callback, with
    ties going to the ``additional_claims`` argument.

- The ``JWT_VERIFY_AUDIENCE`` option has been removed. If you do not want to verify
  the JWT audience (``aud``) claim, simply do not set the ``JWT_DECODE_AUDIENCE``
  option.
- The ``JWT_CLAIMS_IN_REFRESH_TOKEN`` option has been removed. Additional claims
  will now always be put in the JWT regardless of if it is an access or refresh
  tokens. If you don't want additional claims in your refresh tokens, do not
  include any additional claims when creating the refresh token.

New Stuff
~~~~~~~~~
- Add ``locations`` argument to ``@jwt_required()`` and ``verify_jwt_in_request``.
  This will allow you to override the ``JWT_LOCATIONS`` option on a per route basis.
- Revamped and cleaned up documentation. It should be clearer how to work with this
  extension both on the backend and frontend now.
- Lots of code cleanup behind the scenes.
