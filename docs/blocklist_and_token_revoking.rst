.. _Blocklist and Token Revoking:

JWT Revoking / Blocklist
========================
JWT revoking is a mechanism for preventing an otherwise valid JWT from accessing your
routes while still letting other valid JWTs in. To utilize JWT revoking in this
extension, you must defining a callback function via the
:meth:`~flask_jwt_extended.JWTManager.token_in_blocklist_loader` decorator.
This function is called whenever a valid JWT is used to access a protected route.
The callback will receive the JWT header and JWT payload as arguments, and must
return ``True`` if the JWT has been revoked.

In production, you will want to use some form of persistent storage (database,
redis, etc) to store your JWTs. It would be bad if your application forgot that
a JWT was revoked if it was restarted. We can provide some general recommendations
on what type of storage engine to use, but ultimately the choice will depend on
your specific application and tech stack.

Redis
~~~~~
If your only requirements are to check if a JWT has been revoked, our recommendation
is to use redis. It is blazing fast, can be configured to persist data to disc,
and can automatically clear out JWTs after they expire by utilizing the Time To
Live (TTL) functionality when storing a JWT. Here is an example using redis:

.. literalinclude:: ../examples/blocklist_redis.py


.. warning::
    Note that configuring redis to be disk-persistent is an absolutely necessity for
    production use. Otherwise, events like power outages or server crashes/reboots
    would cause all formerly invalidated tokens to become valid again (assuming the
    secret key does not change). This is especially concering for long-lived
    refresh tokens, discussed below.

Database
~~~~~~~~
If you need to keep track of information about revoked JWTs our recommendation is
to utilize a database. This allows you to easily store and utilize metadata for
revoked tokens, such as when it was revoked, who revoked it, can it be un-revoked,
etc. Here is an example using SQLAlchemy:

.. literalinclude:: ../examples/blocklist_database.py

Handling Revoking of Refresh Tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
It is very important to note that a user's refresh token must also be revoked
when logging out; otherwise, this refresh token could just be used to generate
a new access token. Usually this falls to the responsibility of the frontend,
which must

It is very important to note that a user's refresh token(s) must also be revoked
when logging out; otherwise, this refresh token could just be used to generate
a new access token. Usually this falls to the responsibility of the frontend,
which should request 


It is possible to use two different routes with ``@jwt_required()`` and
``@jwt_required(refresh=True)`` to accomplish this. However, it is convenient to
provide a single endpoint where both users 

.. code-block:: python
    @app.route("/logout", methods=["DELETE"])
    @jwt_required(verify_type=False)
    def logout():
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)

        # Returns "Access token revoked" or "Refresh token revoked"
        return jsonify(msg=f"{ttype.capitalize()} token revoked")

or, for the database format:

.. code-block:: python
    class TokenBlocklist(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        jti = db.Column(db.String(36), nullable=False, index=True)
        type = db.Column(db.Integer, nullable=False)
        user_id = db.Column(
            db.ForeignKey('person.id')
            nullable=False,
            default=lambda: get_current_user().id
            )
        created_at = db.Column(db.DateTime, nullable=False)

    @app.route("/logout", methods=["DELETE"])
    @jwt_required(verify_type=False)
    def modify_token():
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        now = datetime.now(timezone.utc)
        db.session.add(TokenBlocklist(jti=jti, type=ttype, created_at=now))
        db.session.commit()
        return jsonify(msg=f"{ttype.capitalize()} token revoked")

Token type and user are not required and can be omitted. That being said, including
these columns can help to audit that the frontend is performing its revoking job
correctly and revoking both tokens.


An alternative, albeit more complex, implementation is to invalidate all issued
tokens at once. 

#. Store all generated access and refresh tokens in a database with a user_id column or similar
#. Change 
#. token_in_blocklist_loader
#. 
