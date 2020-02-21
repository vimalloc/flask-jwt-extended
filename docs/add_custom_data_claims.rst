Storing Data in Access Tokens
=============================

You may want to store additional information in the access token which you could
later access in the protected views. This can be done with the
:meth:`~flask_jwt_extended.JWTManager.user_claims_loader` decorator, and the data can be
accessed later in a protected endpoint with the
:func:`~flask_jwt_extended.get_raw_jwt` function.

Storing data in an access token can be good for performance. If you store data
in the token, you wont need to look it up from disk next time you need it in
a protected endpoint. However, you should take care what data you put in the
token. Any data in the access token can be trivially viewed by anyone who can
read the token. **Do not** store sensitive information in access tokens!

.. literalinclude:: ../examples/additional_data_in_access_token.py
