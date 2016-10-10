Adding Custom Data (Claims) to the Access Token
===============================================

You may want to store additional information in the access token. Perhaps you
want to save the permissions this user has so you can access them in the view
functions, without having to make a database call each time. This can be done
with the user_claims_loader decorator, and accessed later with the
'get_jwt_claims()' method (in a protected endpoint).

.. literalinclude:: ../examples/additional_data_in_access_token.py

Storing data in an access token can be good for performance. If you store data
in the token, you wont need to look it up from disk next time you need it in
a protected endpoint. But be warned, any data in the access token can be easily
viewed with anyone who has access to said token, so refrain from storing
critical data there!
