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
  .. automethod:: decode_key_loader
  .. automethod:: encode_key_loader
  .. automethod:: expired_token_loader
  .. automethod:: invalid_token_loader
  .. automethod:: needs_fresh_token_loader
  .. automethod:: revoked_token_loader
  .. automethod:: token_in_blocklist_loader
  .. automethod:: token_verification_failed_loader
  .. automethod:: token_verification_loader
  .. automethod:: unauthorized_loader
  .. automethod:: user_claims_loader
  .. automethod:: user_identity_loader
  .. automethod:: user_lookup_error_loader
  .. automethod:: user_lookup_loader


Protected endpoint decorators
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: jwt_required


.. _Verify Tokens in Request:

Verify Tokens in Request
~~~~~~~~~~~~~~~~~~~~~~~~
This performs the same actions as the protected endpoint decorators, without
actually decorating a function. This is very useful if you want to create
your own decorators on top of flask jwt extended (such as role_required), or
if you want to hook some of this extensions functionality into a flask
before_request handler.

.. autofunction:: verify_jwt_in_request


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
.. autofunction:: get_jwt_identity
.. autofunction:: get_jwt
.. autofunction:: get_jwt_header
.. autofunction:: set_access_cookies
.. autofunction:: set_refresh_cookies
.. autofunction:: unset_jwt_cookies
