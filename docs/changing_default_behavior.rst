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

Possible loader functions are:

.. list-table::
    :header-rows: 1

    * - Loader Decorator
      - Description
      - Function Arguments
    * - **expired_token_loader**
      - Function to call when an expired token accesses a protected endpoint
      - None
    * - **invalid_token_loader**
      - Function to call when an invalid token accesses a protected endpoint
      - Takes one argument - an error string indicating why the token is invalid
    * - **unauthorized_loader**
      - Function to call when a request with no JWT accesses a protected endpoint
      - Takes one argument - an error string indicating why the request in unauthorized
    * - **needs_fresh_token_loader**
      - Function to call when a non-fresh token accesses a **fresh_jwt_required** endpoint
      - None
    * - **revoked_token_loader**
      - Function to call when a revoked token accesses a protected endpoint
      - None
    * - **user_loader_callback_loader**
      - Function to call to load a user object from a token
      - Takes one argument - The identity of the token to load a user from
    * - **user_loader_error_loader**
      - Function that is called when the user_loader callback function returns **None**
      - Takes one argument - The identity of the user who failed to load

Dynamic token expires time
~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also change the expires time for a token via the **expires_delta** kwarg
in the **create_refresh_token** and **create_access_token** functions. This takes
a **datetime.timedelta** and overrides the **JWT_REFRESH_TOKEN_EXPIRES** and
**JWT_ACCESS_TOKEN_EXPIRES** options. This can be useful if you have different
use cases for different tokens. An example of this might be you use short lived
access tokens used in your web application, but you allow the creation of long
lived access tokens that other developers can generate and use to interact with
your api in their programs.

.. code-block:: python

  @app.route('/create-dev-token', methods=['POST'])
  @jwt_required
  def create_dev_token():
      username = get_jwt_identity()
      expires = datetime.timedelta(days=365)
      token = create_access_token(username, expires_delta=expires)
      return jsonify({'token': token}), 201
