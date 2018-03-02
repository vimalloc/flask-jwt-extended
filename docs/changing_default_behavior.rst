Changing Default Behaviors
==========================

Changing callback functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~

We provide what we think are sensible behaviors when attempting to access a
protected endpoint. If the access token is not valid for any reason (missing,
expired, tampered with, etc) we will return json in the format of {'msg': 'why
accessing endpoint failed'} along with an appropriate http status code
(generally 401 or 422). However, you may want to customize what you return in
some situations. We can do that with the jwt_manager loader functions.


.. literalinclude:: ../examples/loaders.py

Here are the possible loader functions. Click on the links for a more
more details about what arguments your callback functions should expect
and what the return values of your callback functions need to be.

.. list-table::
    :header-rows: 1

    * - Loader Decorator
      - Description
    * - :meth:`~flask_jwt_extended.JWTManager.expired_token_loader`
      - Function to call when an expired token accesses a protected endpoint
    * - :meth:`~flask_jwt_extended.JWTManager.invalid_token_loader`
      - Function to call when an invalid token accesses a protected endpoint
    * - :meth:`~flask_jwt_extended.JWTManager.unauthorized_loader`
      - Function to call when a request with no JWT accesses a protected endpoint
    * - :meth:`~flask_jwt_extended.JWTManager.needs_fresh_token_loader`
      - Function to call when a non-fresh token accesses a :func:`~flask_jwt_extended.fresh_jwt_required` endpoint
    * - :meth:`~flask_jwt_extended.JWTManager.revoked_token_loader`
      - Function to call when a revoked token accesses a protected endpoint
    * - :meth:`~flask_jwt_extended.JWTManager.user_loader_callback_loader`
      - Function to call to load a user object when token accesses a protected endpoint
    * - :meth:`~flask_jwt_extended.JWTManager.user_loader_error_loader`
      - Function that is called when the user_loader callback function returns `None`
    * - :meth:`~flask_jwt_extended.JWTManager.token_in_blacklist_loader`
      - Function that is called to check if a token has been revoked
    * - :meth:`~flask_jwt_extended.JWTManager.claims_verification_loader`
      - Function that is called to verify the user_claims data. Must return True or False
    * - :meth:`~flask_jwt_extended.JWTManager.claims_verification_failed_loader`
      - Function that is called when the user claims verification callback returns False

Dynamic token expires time
~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also change the expires time for a token via the `expires_delta` kwarg
in the :func:`~flask_jwt_extended.create_refresh_token` and
:func:`~flask_jwt_extended.create_access_token` functions. This takes
a `datetime.timedelta` and overrides the `JWT_REFRESH_TOKEN_EXPIRES` and
`JWT_ACCESS_TOKEN_EXPIRES` settings (see :ref:`Configuration Options`).

This can be useful if you have different use cases for different tokens.
For example, you might use short lived access tokens used in your web
application, but you allow the creation of long lived access tokens that other
developers can generate and use to interact with your api in their programs.
You could accomplish this like such:

.. code-block:: python

  @app.route('/create-dev-token', methods=['POST'])
  @jwt_required
  def create_dev_token():
      username = get_jwt_identity()
      expires = datetime.timedelta(days=365)
      token = create_access_token(username, expires_delta=expires)
      return jsonify({'token': token}), 201

You can even disable expiration by setting `expires_delta` to `False`:

.. code-block:: python

  @app.route('/create-api-token', methods=['POST'])
  @jwt_required
  def create_api_token():
      username = get_jwt_identity()
      token = create_access_token(username, expires_delta=False)
      return jsonify({'token': token}), 201

Note that in this case, you should enable token revoking (see :ref:`Blacklist and Token Revoking`).
