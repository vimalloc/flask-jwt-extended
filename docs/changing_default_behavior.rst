Changing Default Behaviors
==========================

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
