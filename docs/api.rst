API Documentation
=================
In here you will find the API for everything exposed in this extension.

Configuring Flask-JWT-Extended
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. currentmodule:: flask_jwt_extended

.. module:: flask_jwt_extended

.. autoclass:: JWTManager

  .. automethod:: __init__
  .. automethod:: init_app
  .. automethod:: claims_verification_loader
  .. automethod:: claims_verification_failed_loader
  .. automethod:: decode_key_loader
  .. automethod:: encode_key_loader
  .. automethod:: expired_token_loader
  .. automethod:: invalid_token_loader
  .. automethod:: needs_fresh_token_loader
  .. automethod:: revoked_token_loader
  .. automethod:: token_in_blacklist_loader
  .. automethod:: unauthorized_loader
  .. automethod:: user_claims_loader
  .. automethod:: user_identity_loader
  .. automethod:: user_loader_callback_loader
  .. automethod:: user_loader_error_loader


Protected endpoint decorators
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: jwt_required
.. autofunction:: jwt_refresh_token_required
.. autofunction:: fresh_jwt_required
.. autofunction:: jwt_optional


.. _Verify Tokens in Request:

Verify Tokens in Request
~~~~~~~~~~~~~~~~~~~~~~~~
These perform the same actions as the protected endpoint decorators, without
actually decorating a function. These are very useful if you want to create
your own decorators on top of flask jwt extended (such as role_required), or
if you want to hook some of this extensions functionality into a flask
before_request handler.

.. autofunction:: verify_jwt_in_request
.. autofunction:: verify_jwt_in_request_optional
.. autofunction:: verify_fresh_jwt_in_request
.. autofunction:: verify_jwt_refresh_token_in_request


Utilities
~~~~~~~~~
.. autofunction:: create_access_token
.. autofunction:: create_refresh_token

.. attribute:: current_user

  A LocalProxy for accessing the current user. Roughly equilivant to
  :func:`~flask_jwt_extended.get_current_user`

.. autofunction:: decode_token
.. autofunction:: get_current_user
.. autofunction:: get_csrf_token
.. autofunction:: get_jti
.. autofunction:: get_jwt_claims
.. autofunction:: get_jwt_identity
.. autofunction:: get_raw_jwt
.. autofunction:: set_access_cookies
.. autofunction:: set_refresh_cookies
.. autofunction:: unset_jwt_cookies
