Storing Data in Access Tokens
=============================

You may want to store additional information in the access token which you could
later access in the protected views. This can be done with the **user_claims_loader**
decorator, and the data can be accessed later in a protected endpoint
with the **get_jwt_claims()** method.

.. literalinclude:: ../examples/additional_data_in_access_token.py

Storing data in an access token can be good for performance. If you store data
in the token, you wont need to look it up from disk next time you need it in
a protected endpoint. However, you should take care what data you put in the
token. Any data in the access token can be easily viewed with anyone who has
access to the token. Take care to avoid storing sensative information in here!
