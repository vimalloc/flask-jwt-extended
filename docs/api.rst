API Documentation
=================
This is the documentation for all of the API that is exported in this extension.

Configuring Flask-JWT-Extended
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. currentmodule:: flask_jwt_extended

.. module:: flask_jwt_extended

.. autoclass:: JWTManager
   :members:


Verify Tokens in Request
~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: jwt_required

.. autofunction:: verify_jwt_in_request


Utilities
~~~~~~~~~
.. autofunction:: create_access_token
.. autofunction:: create_refresh_token
.. attribute:: current_user

    A LocalProxy for accessing the current user. Roughly equilivant to
    :func:`~flask_jwt_extended.get_current_user`

.. autofunction:: decode_token
.. autofunction:: get_csrf_token
.. autofunction:: get_current_user
.. autofunction:: get_jti
.. autofunction:: get_jwt
.. autofunction:: get_jwt_header
.. autofunction:: get_jwt_identity
.. autofunction:: get_unverified_jwt_headers
.. autofunction:: set_access_cookies
.. autofunction:: set_refresh_cookies
.. autofunction:: unset_access_cookies
.. autofunction:: unset_jwt_cookies
.. autofunction:: unset_refresh_cookies
